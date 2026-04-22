#include "bun.h"

static bun_result_t validate_header_basic(const BunHeader *h);

static bun_result_t validate_header_offsets(const BunHeader *h, long file_size);

static bun_result_t validate_asset_record(const BunAssetRecord *rec, const BunHeader *header);

static bun_result_t validate_asset_name(BunParseContext *ctx, const BunHeader *header, const BunAssetRecord *rec);

static bun_result_t validate_compression(const BunAssetRecord *rec);
