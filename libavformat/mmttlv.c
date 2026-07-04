/*
 * MMT protocol over TLV packets (MMT/TLV) demuxer, as defined in ARIB STD-B32.
 * Copyright (c) 2023 SuperFashi
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "config_components.h"

#include "libavutil/mem.h"
#include "libavutil/intreadwrite.h"
#include "avformat.h"
#include "avio_internal.h"
#include "demux.h"
#include "internal.h"
#include "mmtp.h"

#define HEADER_BYTE 0b01111111

enum {
    UNDEFINED_PACKET            = 0x00,
    IPV4_PACKET                 = 0x01,
    IPV6_PACKET                 = 0x02,
    HEADER_COMPRESSED_IP_PACKET = 0x03,
    TRANSMISSION_CONTROL_PACKET = 0xFE,
    NULL_PACKET                 = 0xFF,
};

enum {
    CONTEXT_IDENTIFICATION_PARTIAL_IPV4_AND_PARTIAL_UDP_HEADER = 0x20,
    CONTEXT_IDENTIFICATION_IPV4_HEADER                         = 0x21,
    CONTEXT_IDENTIFICATION_PARTIAL_IPV6_AND_PARTIAL_UDP_HEADER = 0x60,
    CONTEXT_IDENTIFICATION_NO_COMPRESSED_HEADER                = 0x61,
};

static int mmttlv_probe(const AVProbeData *p)
{
    size_t   i;
    uint8_t  packet_type;
    uint16_t data_length;

    int processed  = 0;
    int recognized = 0;

    // Since we always join a live stream mid-packet, the first bytes we see
    // are effectively arbitrary (e.g. compressed video payload) until we
    // happen upon the real packet boundary. Any 0x7F byte within that
    // otherwise-arbitrary data is a candidate "false" sync point; if we
    // don't recognize *and skip past* those quickly, we can burn our whole
    // scan budget (processed < 100) rescanning garbage overlapping bytes one
    // at a time without ever reaching a real, well-formed packet, yielding
    // an unfairly (and sometimes fatally) low score. So: any sync byte
    // followed by a plausible packet_type is treated as recognized and
    // fully skipped via its declared length, regardless of deeper
    // per-type validity (e.g. compressed-IP context identification) which
    // isn't needed just to establish confidence that this is TLV data.
    for (i = 0; i + 4 < p->buf_size && processed < 100;) {
        if (p->buf[i] != HEADER_BYTE) {
            ++i;
            continue;
        }

        packet_type = p->buf[i + 1];
        if (packet_type > 0x04 && packet_type < 0xFD) {
            ++i;
            continue;
        }
        ++processed;

        data_length = AV_RB16(p->buf + i + 2);
        ++recognized;
        i += 4 + data_length;
    }

    return recognized * AVPROBE_SCORE_MAX / FFMAX(processed, 10);
}

struct MMTTLVContext {
    struct Program {
        uint32_t       cid;
        MMTPContext    *mmtp;
        struct Program *next;
    } *programs;

    int64_t last_pos;
    size_t  resync_size;

    size_t  cap;
    uint8_t *buf;
};

static int mmttlv_read_ipv6_packet(
    struct MMTTLVContext *ctx, AVFormatContext *s, AVPacket *pkt,
    const uint8_t *buf, uint16_t size)
{
    uint8_t  next_header;
    uint16_t payload_length;
    uint16_t dst_port;

    // 1. parse ipv6 header
    if (size < 40) return AVERROR_INVALIDDATA;
    next_header = buf[6];
    size -= 40;
    buf += 40;

    if (next_header != 17) return AVERROR_PATCHWELCOME;
    // 2. parse udp header
    if (size < 8) return AVERROR_INVALIDDATA;
    dst_port       = AV_RB16(buf + 2);
    payload_length = AV_RB16(buf + 4);
    // TODO: checksum
    size -= 8;
    buf += 8;

    if (size != payload_length - 8) return AVERROR_INVALIDDATA;
    if (dst_port == 123) {
        // NTP
        return pkt == NULL ? 0 : FFERROR_REDO;
    }
    return AVERROR_PATCHWELCOME;
}

static int mmttlv_read_compressed_ip_packet(
    struct MMTTLVContext *ctx, AVFormatContext *s, AVPacket *pkt,
    const uint8_t *buf, uint16_t size)
{
    // partial udp header are udp header without data length (16 bits) and checksum (16 bits)
#define PARTIAL_UDP_HEADER_LENGTH (8 - 4)
    // partial ipv6 header are ipv6 header without payload length (16 bits)
#define PARTIAL_IPV6_HEADER_LENGTH (40 - 2)

    uint32_t       context_id;
    struct Program *program;

    if (size < 3)
        return AVERROR_INVALIDDATA;
    context_id = AV_RB16(buf) >> 4;
    buf += 3;
    size -= 3;

    for (program = ctx->programs; program != NULL; program = program->next)
        if (program->cid == context_id)
            break;

    if (program == NULL) {
        AVProgram *p = av_new_program(s, context_id);
        if (p == NULL) return AVERROR(errno);

        program = av_malloc(sizeof(struct Program));
        if (program == NULL) return AVERROR(errno);

        program->mmtp = ff_mmtp_parse_open(p);
        program->next = ctx->programs;
        ctx->programs = program;
        program->cid  = context_id;
    }

    switch (buf[-1]) {
    case CONTEXT_IDENTIFICATION_PARTIAL_IPV4_AND_PARTIAL_UDP_HEADER:
    case CONTEXT_IDENTIFICATION_IPV4_HEADER:
        return AVERROR_PATCHWELCOME;
    case CONTEXT_IDENTIFICATION_PARTIAL_IPV6_AND_PARTIAL_UDP_HEADER:
        if (size < PARTIAL_IPV6_HEADER_LENGTH + PARTIAL_UDP_HEADER_LENGTH)
            return AVERROR_INVALIDDATA;
        size -= PARTIAL_IPV6_HEADER_LENGTH + PARTIAL_UDP_HEADER_LENGTH;
        buf += PARTIAL_IPV6_HEADER_LENGTH + PARTIAL_UDP_HEADER_LENGTH;
    case CONTEXT_IDENTIFICATION_NO_COMPRESSED_HEADER:
        break;
    default:
        return AVERROR_INVALIDDATA;
    }

    return ff_mmtp_parse_packet(program->mmtp, s, pkt, buf, size);
}

// A byte immediately following a sync byte is only plausibly a TLV
// packet_type if it is one of the defined values below. Requiring this at
// every candidate sync point (both the initial and the lookahead one)
// considerably reduces the odds of locking onto a coincidental 0x7F byte
// inside otherwise-arbitrary (e.g. compressed video) packet payload data.
static int mmttlv_valid_packet_type(uint8_t type)
{
    switch (type) {
    case UNDEFINED_PACKET:
    case IPV4_PACKET:
    case IPV6_PACKET:
    case HEADER_COMPRESSED_IP_PACKET:
    case TRANSMISSION_CONTROL_PACKET:
    case NULL_PACKET:
        return 1;
    default:
        return 0;
    }
}

// Resynchronize to a TLV packet boundary by scanning for a sync byte
// (HEADER_BYTE) followed by a plausible packet_type, whose declared length
// leads to another such sync byte + packet_type pair. This is retried
// whenever synchronization is lost, not just once after a seek, since a
// live, variable-length-packet stream can be joined mid-packet at any byte
// offset and a single false lock would otherwise corrupt all further
// parsing with no way to recover.
static int mmttlv_resync(AVFormatContext *s, struct MMTTLVContext *ctx)
{
    uint8_t header[4];
    uint16_t size;
    int err;
    int64_t pos = avio_tell(s->pb);

    if (pos < 0) return (int) pos;
    ctx->last_pos = pos;

    while (pos - ctx->last_pos < ctx->resync_size) {
        if ((err = ffio_ensure_seekback(s->pb, 4)) < 0)
            return err;

        if ((err = avio_read(s->pb, header, 4)) < 0)
            return avio_feof(s->pb) ? AVERROR_EOF : err;

        if (header[0] != HEADER_BYTE || !mmttlv_valid_packet_type(header[1])) {
            if ((pos = avio_seek(s->pb, -3, SEEK_CUR)) < 0)
                return (int) pos;
            continue;
        }

        size = AV_RB16(header + 2);

        if ((pos = avio_seek(s->pb, -4, SEEK_CUR)) < 0)
            return (int) pos;

        if ((err = ffio_ensure_seekback(s->pb, 4 + size + 2)) < 0)
            return err;

        if ((pos = avio_skip(s->pb, 4 + size)) < 0)
            return (int) pos;

        if ((err = avio_read(s->pb, header, 2)) < 0)
            return avio_feof(s->pb) ? AVERROR_EOF : err;

        if (header[0] == HEADER_BYTE && mmttlv_valid_packet_type(header[1])) {
            // found HEADER, [size], HEADER, packet_type, should be good
            if ((pos = avio_seek(
                s->pb, -(int64_t) (size) - 2 - 4, SEEK_CUR)) < 0)
                return (int) pos;
            goto success;
        }

        if ((pos = avio_seek(
            s->pb, -(int64_t) (size) - 2 - 3, SEEK_CUR)) < 0)
            return (int) pos;
    }
    return AVERROR_INVALIDDATA;

    success:
    ctx->last_pos = pos;

    for (struct Program *program = ctx->programs;
         program != NULL; program = program->next)
        ff_mmtp_reset_state(program->mmtp);
    return 0;
}

static int mmttlv_read_packet(AVFormatContext *s, AVPacket *pkt)
{
    uint8_t              header[4];
    uint16_t             size;
    int                  err;
    struct MMTTLVContext *ctx = s->priv_data;
    int64_t              pos  = avio_tell(s->pb);

    if (pos < 0) return (int) pos;
    if (pos != ctx->last_pos) {
        if ((err = mmttlv_resync(s, ctx)) < 0)
            return err;
    }

    if (pkt != NULL) pkt->pos = ctx->last_pos;
    if ((err = ffio_read_size(s->pb, header, 4)) < 0)
        return avio_feof(s->pb) ? AVERROR_EOF : err;
    ctx->last_pos += 4;

    if (header[0] != HEADER_BYTE || !mmttlv_valid_packet_type(header[1])) {
        // Lost synchronization mid-stream (e.g. a corrupted or dropped
        // packet threw off the byte offset). Rather than failing the whole
        // demux outright, try to reacquire sync from here, same as we do
        // right after opening/seeking.
        if ((pos = avio_seek(s->pb, -4, SEEK_CUR)) < 0)
            return (int) pos;
        if ((err = mmttlv_resync(s, ctx)) < 0)
            return err;
        if ((err = ffio_read_size(s->pb, header, 4)) < 0)
            return avio_feof(s->pb) ? AVERROR_EOF : err;
        ctx->last_pos += 4;
        if (header[0] != HEADER_BYTE || !mmttlv_valid_packet_type(header[1]))
            return AVERROR_INVALIDDATA;
    }

    size = AV_RB16(header + 2);
    if (header[1] == NULL_PACKET) {
        if ((ctx->last_pos = avio_skip(s->pb, size)) < 0)
            return (int) ctx->last_pos;
        return pkt == NULL ? 0 : FFERROR_REDO;
    }

    if (ctx->cap < size) {
        av_free(ctx->buf);
        if ((ctx->buf = av_malloc(ctx->cap = size)) == NULL)
            return AVERROR(errno);
    }
    if ((err = ffio_read_size(s->pb, ctx->buf, size)) < 0)
        return avio_feof(s->pb) ? AVERROR_EOF : err;
    ctx->last_pos += size;

    switch (header[1]) {
    case IPV6_PACKET:
        return mmttlv_read_ipv6_packet(ctx, s, pkt, ctx->buf, size);
    case HEADER_COMPRESSED_IP_PACKET:
        return mmttlv_read_compressed_ip_packet(ctx, s, pkt, ctx->buf, size);
    default:
        return AVERROR_PATCHWELCOME;
    }
}

static int mmttlv_read_header(AVFormatContext *s)
{
    int64_t              pos;
    int64_t              allow = s->probesize;
    struct MMTTLVContext *ctx  = s->priv_data;

    ctx->last_pos = avio_tell(s->pb);
    if (ctx->last_pos < 0)
        return (int) ctx->last_pos;
    ctx->last_pos -= 1; // force resync

    ctx->resync_size = 4096;
    s->ctx_flags |= AVFMTCTX_NOHEADER;

    if (!s->pb->seekable)
        return 0;

    if ((pos = avio_tell(s->pb)) < 0)
        return (int) pos;

    while (s->nb_streams <= 0 && allow > 0) {
        const int64_t cur = ctx->last_pos;
        const int     err = mmttlv_read_packet(s, NULL);
        // FFERROR_REDO just means "no output from this call, try again",
        // e.g. because fill_pts_dts() isn't ready to timestamp an audio/
        // video unit yet. It is not a real failure (see how
        // mmttlv_read_timestamp() already treats it below) and must not
        // abort this stream-discovery pre-scan.
        if (err < 0 && err != FFERROR_REDO) return err;
        allow -= ctx->last_pos - cur;
    }

    ctx->last_pos = avio_tell(s->pb);
    if (ctx->last_pos < 0)
        return (int) ctx->last_pos;

    if ((pos = avio_seek(s->pb, pos, SEEK_SET)) < 0)
        return (int) pos;

    return 0;
}

static int mmttlv_read_close(AVFormatContext *ctx)
{
    struct Program       *program;
    struct MMTTLVContext *priv = ctx->priv_data;
    for (program = priv->programs; program != NULL;) {
        struct Program *next = program->next;
        ff_mmtp_parse_close(program->mmtp);
        av_free(program);
        program = next;
    }
    priv->programs = NULL;
    priv->cap      = 0;
    av_freep(&priv->buf);
    return 0;
}

static int64_t mmttlv_read_timestamp(
    struct AVFormatContext *s, int stream_index,
    int64_t *pos, int64_t pos_limit)
{
    struct MMTTLVContext *ctx = s->priv_data;

    if ((*pos = avio_seek(s->pb, *pos, SEEK_SET)) < 0)
        return (int) *pos;

    while (pos_limit > 0) {
        AVPacket      packet = {0};
        const int     err    = mmttlv_read_packet(s, &packet);
        const int64_t ts     = packet.dts;
        const int64_t off    = packet.pos;
        const int     sid    = packet.stream_index;
        av_packet_unref(&packet);
        if (err >= 0 && (stream_index < 0 || sid == stream_index)) {
            *pos = off;
            return ts;
        }
        pos_limit -= ctx->last_pos - *pos;
        *pos = ctx->last_pos;
        if (err < 0 && err != FFERROR_REDO)
            return AV_NOPTS_VALUE;
    }

    return AV_NOPTS_VALUE;
}

#if CONFIG_MMTTLV_DEMUXER
const FFInputFormat ff_mmttlv_demuxer = {
    .p.name         = "mmttlv",
    .p.long_name    = NULL_IF_CONFIG_SMALL(
        "MMT protocol over TLV packets (ARIB STD-B32)"),
    .p.flags        = AVFMT_SHOW_IDS,
    .priv_data_size = sizeof(struct MMTTLVContext),
    .flags_internal = FF_INFMT_FLAG_INIT_CLEANUP,
    .read_probe     = mmttlv_probe,
    .read_header    = mmttlv_read_header,
    .read_packet    = mmttlv_read_packet,
    .read_close     = mmttlv_read_close,
    .read_timestamp = mmttlv_read_timestamp,
};
#endif