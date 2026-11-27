/* spy_patch.c -- see spy_patch.h. */
#include "spy_patch.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define PT_LOAD 1u
#define PF_X 1u
#define PF_W 2u
#define PF_R 4u
#define VADDR_BASE 0x8000u
#define PHDR_OFF_FILESZ 16u
#define PHDR_OFF_MEMSZ 20u

#define MODFAC_CONSTRUCT_SLOT 7u
#define ORIG_LIT_OFF 0x80u /* offset of the .word holding ModFac_construct inside the trampoline (assembled: 0x209bc8) */

/* Assembled from the spy trampoline source (ARM, 148 bytes incl. literals):
 * saves r0-r7/r12/lr, builds the record on the stack, open(O_APPEND)/write/
 * close on /tmp/modfac.bin, restores everything, jumps to the original. */
static const uint8_t k_spy_tramp[148] = {
  0xff, 0x50, 0x2d, 0xe9, 0x40, 0xd0, 0x4d, 0xe2, 0x68, 0x40, 0x8d, 0xe2,
  0x40, 0x50, 0x9d, 0xe5, 0x44, 0x60, 0x9d, 0xe5, 0x64, 0x70, 0x9d, 0xe5,
  0xe0, 0x00, 0x8d, 0xe8, 0x0c, 0x40, 0x8d, 0xe5, 0x10, 0x50, 0x8d, 0xe2,
  0x0f, 0x00, 0xb4, 0xe8, 0x0f, 0x00, 0xa5, 0xe8, 0x0f, 0x00, 0xb4, 0xe8,
  0x0f, 0x00, 0xa5, 0xe8, 0x0f, 0x00, 0xb4, 0xe8, 0x0f, 0x00, 0xa5, 0xe8,
  0x40, 0x00, 0x8f, 0xe2, 0x41, 0x14, 0x00, 0xe3, 0x69, 0x2f, 0xa0, 0xe3,
  0x05, 0x70, 0xa0, 0xe3, 0x00, 0x00, 0x00, 0xef, 0x00, 0x40, 0xb0, 0xe1,
  0x06, 0x00, 0x00, 0x4a, 0x0d, 0x10, 0xa0, 0xe1, 0x40, 0x20, 0xa0, 0xe3,
  0x04, 0x70, 0xa0, 0xe3, 0x00, 0x00, 0x00, 0xef, 0x04, 0x00, 0xa0, 0xe1,
  0x06, 0x70, 0xa0, 0xe3, 0x00, 0x00, 0x00, 0xef, 0x40, 0xd0, 0x8d, 0xe2,
  0xff, 0x50, 0xbd, 0xe8, 0x04, 0xf0, 0x1f, 0xe5, 0xc8, 0x9b, 0x20, 0x00,
  0x2f, 0x74, 0x6d, 0x70, 0x2f, 0x6d, 0x6f, 0x64, 0x66, 0x61, 0x63, 0x2e,
  0x62, 0x69, 0x6e, 0x00,
};

static uint32_t rd32(const uint8_t* d, size_t off)
{
  return (uint32_t)d[off] | ((uint32_t)d[off + 1] << 8) | ((uint32_t)d[off + 2] << 16) | ((uint32_t)d[off + 3] << 24);
}

static void wr32(uint8_t* d, size_t off, uint32_t v)
{
  d[off] = (uint8_t)v;
  d[off + 1] = (uint8_t)(v >> 8);
  d[off + 2] = (uint8_t)(v >> 16);
  d[off + 3] = (uint8_t)(v >> 24);
}

static void set_err(char* err, size_t err_size, const char* fmt, ...)
{
  if (!err || err_size == 0)
    return;
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(err, err_size, fmt, ap);
  va_end(ap);
}

/* Reserves `need` bytes (word-aligned) of dead space right after the R+E
 * LOAD segment's file end, the same reclaimed gap patch_gonkulator uses, and
 * grows that segment's filesz/memsz to cover it. The bytes must be zero and
 * not inside any other PT_LOAD's file range. Returns file offset and vaddr. */
static bool cave_alloc(uint8_t* data, size_t data_len, uint32_t need, uint32_t* out_off, uint32_t* out_vaddr,
                       char* err, size_t err_size)
{
  uint32_t e_phoff = rd32(data, 28);
  uint16_t e_phentsize = (uint16_t)(data[42] | (data[43] << 8));
  uint16_t e_phnum = (uint16_t)(data[44] | (data[45] << 8));
  if ((size_t)e_phoff + (size_t)e_phentsize * e_phnum > data_len)
  {
    set_err(err, err_size, "program header table out of bounds");
    return false;
  }

  need = (need + 3u) & ~3u;
  int code_idx = -1, code_count = 0;
  for (uint16_t i = 0; i < e_phnum; ++i)
  {
    size_t off = (size_t)e_phoff + (size_t)i * e_phentsize;
    if (rd32(data, off) == PT_LOAD && rd32(data, off + 24) == (PF_R | PF_X))
    {
      code_idx = i;
      code_count++;
    }
  }
  if (code_count != 1)
  {
    set_err(err, err_size, "REFUSING: expected exactly one plain R+E LOAD segment, found %d", code_count);
    return false;
  }
  size_t cph = (size_t)e_phoff + (size_t)code_idx * e_phentsize;
  uint32_t c_off = rd32(data, cph + 4), c_vaddr = rd32(data, cph + 8);
  uint32_t c_filesz = rd32(data, cph + 16), c_memsz = rd32(data, cph + 20);
  if (c_filesz != c_memsz)
  {
    set_err(err, err_size, "REFUSING: code segment filesz != memsz");
    return false;
  }

  uint32_t cave_off = c_off + c_filesz;
  if ((size_t)cave_off + need > data_len)
  {
    set_err(err, err_size, "REFUSING: code cave runs past end of file");
    return false;
  }
  for (uint16_t i = 0; i < e_phnum; ++i)
  {
    size_t off = (size_t)e_phoff + (size_t)i * e_phentsize;
    if (rd32(data, off) != PT_LOAD || (int)i == code_idx)
      continue;
    uint32_t o = rd32(data, off + 4);
    if (o < cave_off + need && o + rd32(data, off + 16) > cave_off)
    {
      set_err(err, err_size, "REFUSING: code cave overlaps another PT_LOAD segment");
      return false;
    }
  }
  for (uint32_t i = 0; i < need; ++i)
  {
    if (data[cave_off + i] != 0)
    {
      set_err(err, err_size, "REFUSING: code cave not zero at file offset 0x%x (already patched?)",
              (unsigned)(cave_off + i));
      return false;
    }
  }

  wr32(data, cph + PHDR_OFF_FILESZ, c_filesz + need);
  wr32(data, cph + PHDR_OFF_MEMSZ, c_memsz + need);
  *out_off = cave_off;
  *out_vaddr = c_vaddr + c_filesz;
  return true;
}

bool nam_elf_patch_modfac_spy(const SpyTarget* t, uint8_t* data, size_t data_len, uint32_t* out_tramp, char* err,
                              size_t err_size)
{
  if (data_len < 52 || memcmp(data, "\x7f" "ELF", 4) != 0 || data[4] != 1 || data[5] != 1)
  {
    set_err(err, err_size, "not a 32-bit little-endian ELF");
    return false;
  }
  if (!t->modfac_vtable)
  {
    set_err(err, err_size, "the ModFac spy has no target for %s", t->model);
    return false;
  }
  uint32_t slot_vaddr = t->modfac_vtable + MODFAC_CONSTRUCT_SLOT * 4;
  uint32_t slot_off = slot_vaddr - VADDR_BASE;
  if ((size_t)slot_off + 4 > data_len || rd32(data, slot_off) != t->modfac_construct)
  {
    set_err(err, err_size,
            "REFUSING: ModFac vtable slot @ 0x%x does not hold 0x%x (wrong binary / already patched / not %s 2.7).",
            (unsigned)slot_vaddr, (unsigned)t->modfac_construct, t->model);
    return false;
  }

  uint32_t cave_off, tramp_vaddr;
  if (!cave_alloc(data, data_len, (uint32_t)sizeof(k_spy_tramp), &cave_off, &tramp_vaddr, err, err_size))
    return false;
  uint32_t len = (uint32_t)sizeof(k_spy_tramp);
  memcpy(data + cave_off, k_spy_tramp, len);
  if (rd32(data, cave_off + ORIG_LIT_OFF) != 0x209bc8u)
  {
    set_err(err, err_size, "internal error: trampoline literal offset is wrong");
    return false;
  }
  wr32(data, cave_off + ORIG_LIT_OFF, t->modfac_construct);
  wr32(data, slot_off, tramp_vaddr);

  if (out_tramp)
    *out_tramp = tramp_vaddr;
  return true;
}

/* Addresses in the comments below are the Pedalboard 2.7's; each model's own are in its SpyTarget (spy_targets.c). */

/* ---- pedal registry: add one extra "<name>" / "<name> 2" pair -----------------------------------------------
 *
 * The UI identifies a pedal by its index k into the name array: 0 = "Empty Slot", 1..166 = normal pedals (each
 * type listed twice, "X" and "X 2"), 167 = "FX-Loop" (special). Everything per-pedal is a parallel 168-word table
 * indexed by k (names, short names, category X, descriptor tables P1-P4, T5), the ctor's type-index array, and
 * a pile of compares against 0xa5..0xa8 that mean "normal range" / "is FX-Loop". Appending a pair therefore means:
 * every table grows by two entries (FX-Loop moves from 167 to 169), every reader is repointed at the new copy,
 * and the hard-coded constants are bumped by 2. Tables that cannot be extended in place are relocated into the
 * R+E gap and the zero slack at the end of the R+W segment. Every patched word is checked against its expected
 * old value first. */

/* Same pedal list on every model (checked when the targets were derived): 168 names, 166 typed entries. */
#define REG_NAME_COUNT 168u
#define REG_TYPE_COUNT 166u
#define REG_TABLE_BYTES (REG_NAME_COUNT * 4u)

/* ---- picker catalog hook ----------------------------------------------------------------------------------------
 *
 * The block-type picker's category -> pedal-name lists are built by a static initializer (fcn 0x66288) from
 * literal names: arrays of std::string in consecutive stack slots, turned into vectors by fcn 0x59c0f0(out, array,
 * count). The "Distortion" list is built by the `bl 0x59c0f0` at 0x665ac (count 0x12). The arrays cannot grow in
 * place, so that call is redirected through a veneer (parked in the dead body of ModFac_construct case 84, a type
 * no registry entry builds) to a hook in the cave. The hook rebuilds the array on its own stack with the extra
 * names appended and calls the original builder with the larger count. */
#define CAT_HOOK_LIT_OFF 196u

static const uint8_t k_cat_hook[208] = {
  0xf0, 0x5f, 0x2d, 0xe9, 0x00, 0x40, 0xa0, 0xe1, 0x01, 0x50, 0xa0, 0xe1,
  0x02, 0x60, 0xa0, 0xe1, 0x03, 0x70, 0xa0, 0xe1, 0x00, 0x80, 0x97, 0xe5,
  0x08, 0x90, 0x86, 0xe0, 0x18, 0x00, 0xa0, 0xe3, 0x99, 0x00, 0x0b, 0xe0,
  0x0b, 0xd0, 0x4d, 0xe0, 0x0d, 0xa0, 0xa0, 0xe1, 0x00, 0xb0, 0xa0, 0xe3,
  0x06, 0x00, 0x5b, 0xe1, 0x0c, 0x00, 0x00, 0xaa, 0x18, 0x30, 0xa0, 0xe3,
  0x9b, 0x03, 0x03, 0xe0, 0x03, 0x00, 0x8a, 0xe0, 0x03, 0x10, 0x85, 0xe0,
  0x08, 0x30, 0x80, 0xe2, 0x00, 0x30, 0x80, 0xe5, 0x04, 0x20, 0x91, 0xe5,
  0x00, 0x10, 0x91, 0xe5, 0x02, 0x20, 0x81, 0xe0, 0x60, 0xc0, 0x9f, 0xe5,
  0x3c, 0xff, 0x2f, 0xe1, 0x01, 0xb0, 0x8b, 0xe2, 0xf0, 0xff, 0xff, 0xea,
  0x00, 0xb0, 0xa0, 0xe3, 0x08, 0x00, 0x5b, 0xe1, 0x09, 0x00, 0x00, 0xaa,
  0x0b, 0x30, 0x86, 0xe0, 0x18, 0x20, 0xa0, 0xe3, 0x93, 0x02, 0x03, 0xe0,
  0x03, 0x00, 0x8a, 0xe0, 0x04, 0x10, 0x87, 0xe2, 0x0b, 0x11, 0x91, 0xe7,
  0x30, 0xc0, 0x9f, 0xe5, 0x3c, 0xff, 0x2f, 0xe1, 0x01, 0xb0, 0x8b, 0xe2,
  0xf3, 0xff, 0xff, 0xea, 0x04, 0x00, 0xa0, 0xe1, 0x0a, 0x10, 0xa0, 0xe1,
  0x09, 0x20, 0xa0, 0xe1, 0x18, 0xc0, 0x9f, 0xe5, 0x3c, 0xff, 0x2f, 0xe1,
  0x18, 0x30, 0xa0, 0xe3, 0x99, 0x03, 0x03, 0xe0, 0x03, 0xd0, 0x8d, 0xe0,
  0xf0, 0x9f, 0xbd, 0xe8, 0xe0, 0x48, 0x5b, 0x00, 0x84, 0x2e, 0x5b, 0x00,
  0xf0, 0xc0, 0x59, 0x00,
};

/* Reserves `need` bytes (word-aligned) of zero slack after the R+W LOAD segment's file-backed end, before the next
 * page boundary, and grows that segment's p_filesz to cover them. The file bytes there are trailing non-loaded
 * data (section tables) and get overwritten. */
static bool rw_tail_alloc(uint8_t* data, size_t data_len, uint32_t need, uint32_t* out_off, uint32_t* out_vaddr,
                          char* err, size_t err_size)
{
  uint32_t e_phoff = rd32(data, 28);
  uint16_t e_phentsize = (uint16_t)(data[42] | (data[43] << 8));
  uint16_t e_phnum = (uint16_t)(data[44] | (data[45] << 8));
  need = (need + 3u) & ~3u;
  int rw = -1, count = 0;
  for (uint16_t i = 0; i < e_phnum; ++i)
  {
    size_t off = (size_t)e_phoff + (size_t)i * e_phentsize;
    if (rd32(data, off) == PT_LOAD && rd32(data, off + 24) == (PF_R | PF_W))
    {
      rw = i;
      count++;
    }
  }
  if (count != 1)
  {
    set_err(err, err_size, "REFUSING: expected exactly one plain R+W LOAD segment, found %d", count);
    return false;
  }
  size_t ph = (size_t)e_phoff + (size_t)rw * e_phentsize;
  uint32_t p_off = rd32(data, ph + 4), p_vaddr = rd32(data, ph + 8);
  uint32_t filesz = rd32(data, ph + 16), memsz = rd32(data, ph + 20);
  uint32_t vend = p_vaddr + filesz;
  uint32_t page_end = (vend + 0xfffu) & ~0xfffu;
  if (filesz + need > memsz || vend + need > page_end || (size_t)p_off + filesz + need > data_len)
  {
    set_err(err, err_size,
            "REFUSING: not enough slack after the R+W segment (need %u, have %u before the page end)", (unsigned)need,
            (unsigned)(page_end - vend));
    return false;
  }
  wr32(data, ph + 16, filesz + need);
  *out_off = p_off + filesz;
  *out_vaddr = vend;
  memset(data + *out_off, 0, need);
  return true;
}

/* Rewrites a movw/movt pair at `vaddr` (movw) / vaddr+4 (movt) from `old_val` to `new_val`, same register. */
static bool patch_movw_movt(uint8_t* data, size_t data_len, uint32_t vaddr, uint32_t old_val, uint32_t new_val,
                            char* err, size_t err_size)
{
  uint32_t off = vaddr - VADDR_BASE;
  if ((size_t)off + 8 > data_len)
  {
    set_err(err, err_size, "movw/movt site 0x%x out of bounds", (unsigned)vaddr);
    return false;
  }
  uint32_t lo = rd32(data, off), hi = rd32(data, off + 4);
  uint32_t lo_val = ((lo >> 4) & 0xF000u) | (lo & 0xFFFu);
  uint32_t hi_val = ((hi >> 4) & 0xF000u) | (hi & 0xFFFu);
  uint32_t rd_lo = (lo >> 12) & 15u, rd_hi = (hi >> 12) & 15u;
  if ((lo & 0x0FF00000u) != 0x03000000u || (hi & 0x0FF00000u) != 0x03400000u || rd_lo != rd_hi
      || ((hi_val << 16) | lo_val) != old_val)
  {
    set_err(err, err_size, "REFUSING: movw/movt @ 0x%x does not load 0x%x (wrong binary / already patched).",
            (unsigned)vaddr, (unsigned)old_val);
    return false;
  }
  wr32(data, off, (lo & 0xFFF0F000u) | (((new_val >> 12) & 0xFu) << 16) | (new_val & 0xFFFu));
  wr32(data, off + 4, (hi & 0xFFF0F000u) | ((((new_val >> 16) >> 12) & 0xFu) << 16) | ((new_val >> 16) & 0xFFFu));
  return true;
}

static bool check_word(const uint8_t* data, size_t data_len, uint32_t vaddr, uint32_t want, const char* what, char* err,
                       size_t err_size)
{
  uint32_t off = vaddr - VADDR_BASE;
  if ((size_t)off + 4 > data_len || rd32(data, off) != want)
  {
    set_err(err, err_size, "REFUSING: %s @ 0x%x does not hold 0x%x (wrong binary / already patched).", what,
            (unsigned)vaddr, (unsigned)want);
    return false;
  }
  return true;
}

#define NAM_MAX_IDS 8u

/* Instances (ids) one pedal entry owns: 2 (a pair) or 4. */
static uint32_t nam_pair_instances(const NamPair* p)
{
  return p->instances ? p->instances : 2;
}

/* Validates the pedal list and returns the number of extra ids. One entry may own 4 ids, but then it must be the only
 * entry: the picker maps a row to its first id as 2*row-1, which only holds for pairs and for the first extra row. */
static bool nam_pairs_ids(const NamPair* pairs, uint32_t n, uint32_t* out_ids, char* err, size_t err_size)
{
  uint32_t ids = 0;
  if (n < 1 || n > NAM_MAX_PAIRS)
  {
    set_err(err, err_size, "pedal count %u out of range 1..%u", (unsigned)n, (unsigned)NAM_MAX_PAIRS);
    return false;
  }
  for (uint32_t p = 0; p < n; ++p)
  {
    uint32_t inst = nam_pair_instances(&pairs[p]);
    if (inst != 2 && inst != 4)
    {
      set_err(err, err_size, "a pedal has 2 or 4 instances, not %u", (unsigned)inst);
      return false;
    }
    if (inst == 4 && n != 1)
    {
      set_err(err, err_size, "a 4-instance pedal must be the only extra pedal");
      return false;
    }
    ids += inst;
  }
  if (ids > NAM_MAX_IDS)
  {
    set_err(err, err_size, "at most %u extra ids", (unsigned)NAM_MAX_IDS);
    return false;
  }
  *out_ids = ids;
  return true;
}

static uint32_t id_site_add(int kind, uint32_t ids, uint32_t rows)
{
  return kind == NAM_ID_PAIR ? rows : kind == NAM_ID_TAIL ? ids - rows : kind == NAM_ID_SHIFT ? ids : 4 * ids;
}

/* Copies old[0..166], then old[165], old[166] alternating for every extra id (an extra pedal clones the last normal
 * pair: odd ids are "X", even ids "X 2"), then old[167] (FX-Loop). In-place extension is safe because the three
 * source words are read first. */
static void extend_table(uint8_t* data, uint32_t old_off, uint32_t dst_off, uint32_t nids)
{
  uint32_t t165 = rd32(data, old_off + 165 * 4), t166 = rd32(data, old_off + 166 * 4), t167 = rd32(data, old_off + 167 * 4);
  if (dst_off != old_off)
    for (uint32_t i = 0; i < 167; ++i)
      wr32(data, dst_off + i * 4, rd32(data, old_off + i * 4));
  for (uint32_t i = 0; i < nids; ++i)
    wr32(data, dst_off + (167 + i) * 4, (i & 1) ? t166 : t165);
  wr32(data, dst_off + (167 + nids) * 4, t167);
}

/* Returns an ARM data-processing word whose rotated 8-bit immediate is the old one plus `add` (0 if not encodable). */
static uint32_t bump_imm(uint32_t w, uint32_t add)
{
  uint32_t imm = w & 0xffu, rot = ((w >> 8) & 15u) * 2u;
  uint32_t val = rot ? ((imm >> rot) | (imm << (32 - rot))) : imm;
  val += add;
  for (uint32_t r = 0; r < 16; ++r)
  {
    uint32_t rotated = r ? ((val << (2 * r)) | (val >> (32 - 2 * r))) : val;
    if (rotated <= 0xffu)
      return (w & 0xfffff000u) | (r << 8) | rotated;
  }
  return 0;
}

bool nam_elf_patch_registry(const SpyTarget* t, uint8_t* data, size_t data_len, const NamPair* pairs, uint32_t npairs,
                            char* err, size_t err_size)
{
  uint32_t D = 0;
  if (!nam_pairs_ids(pairs, npairs, &D, err, err_size))
    return false;
  const uint32_t R = npairs; /* extra picker rows */
  /* ---- 1. verify everything we are about to touch ---- */
  struct
  {
    uint32_t vaddr, want;
    const char* what;
  } checks[] = {
      {t->types_start_lit, t->types_start, "types start literal"},
      {t->types_end_lit, t->types_end, "types end literal"},
      {t->names_lit_ctor, t->names_base - 4, "ctor names literal"},
      {t->names_lit_map, t->names_base - 4, "map names literal"},
      {t->map_end_insn, t->map_end_insn_old, "name-array end instruction"},
      {t->cmp_last_idx, t->cmp_last_idx_old, "ctor last-index compare"},
      {t->cmp_count, t->cmp_count_old, "ctor name-count compare"},
      {t->memset_sz, t->memset_sz_old, "ctor prototype-table memset size"},
      {t->statemap_new_a, t->statemap_new_a_old, "StateMap-sized allocation A"},
      {t->statemap_new_b, t->statemap_new_b_old, "StateMap-sized allocation B"},
      {t->short_loop_cmp, t->short_loop_cmp_old, "short-name loop bound"},
      {t->cat_call_site, t->cat_call_site_old, "picker catalog call site"},
      {(t->modfac_jt + 84u * 4u), t->cat_veneer, "dead case-84 jump table slot"},
      {t->cat2_call_site, t->cat2_call_site_old, "picker Reverb-category call site"},
      {(t->modfac_jt + 82u * 4u), t->cat2_veneer, "dead case-82 jump table slot"},
      {t->cat2_veneer, t->cat2_veneer_old, "dead case-82 body"},
  };
  for (size_t i = 0; i < sizeof(checks) / sizeof(checks[0]); ++i)
    if (!check_word(data, data_len, checks[i].vaddr, checks[i].want, checks[i].what, err, err_size))
      return false;
  for (size_t i = 0; i < NAM_MAX_NAME_READERS && t->names16_lits[i]; ++i)
    if (!check_word(data, data_len, t->names16_lits[i], t->names_base + 16, "names+16 literal", err, err_size))
      return false;
  for (size_t i = 0; i < t->n_id_sites; ++i)
  {
    if (!check_word(data, data_len, t->id_sites[i].vaddr, t->id_sites[i].old_w, "id-space constant", err, err_size))
      return false;
    uint32_t add = id_site_add(t->id_sites[i].kind, D, R);
    if (!bump_imm(t->id_sites[i].old_w, add))
    {
      set_err(err, err_size, "id-space constant @ 0x%x cannot be encoded for %u pairs", (unsigned)t->id_sites[i].vaddr,
              (unsigned)npairs);
      return false;
    }
  }
  if (t->types_end - t->types_start != REG_TYPE_COUNT * 4)
  {
    set_err(err, err_size, "internal error: type array size constants disagree");
    return false;
  }
  /* sanity: the name array's FX-Loop sits at 167 and every table's last normal entries are a pair */
  for (size_t ti = 0; ti < t->ntables; ++ti)
  {
    uint32_t o = t->tables[ti].base - VADDR_BASE;
    bool pair_ok = t->tables[ti].distinct_pair ? rd32(data, o + 165 * 4) != rd32(data, o + 166 * 4)
                                                : rd32(data, o + 165 * 4) == rd32(data, o + 166 * 4);
    if ((size_t)o + REG_TABLE_BYTES + 4 * D > data_len || !pair_ok
        || rd32(data, o + 167 * 4) == rd32(data, o + 166 * 4))
    {
      set_err(err, err_size, "REFUSING: %s @ 0x%x does not have the expected pair layout (already patched?).",
              t->tables[ti].what, (unsigned)t->tables[ti].base);
      return false;
    }
  }
  for (uint32_t p = 0; p < npairs; ++p)
    if (strlen(pairs[p].name) > 12 || strlen(pairs[p].short_name) > 12)
    {
      set_err(err, err_size, "pedal names are limited to 12 characters (\" 2\" is appended)");
      return false;
    }

  /* ---- 2. allocate ---- */
  uint32_t str_bytes = 0, hook_names = 0;
  for (uint32_t p = 0; p < npairs; ++p)
  {
    size_t name_len = strlen(pairs[p].name), short_len = strlen(pairs[p].short_name);
    uint32_t inst = nam_pair_instances(&pairs[p]);
    str_bytes += (uint32_t)((name_len + 1) + (inst - 1) * (name_len + 3) + (short_len + 1) + (inst - 1) * (short_len + 3));
    hook_names += (uint32_t)((name_len + 1 + 3) & ~3u);
  }
  uint32_t types_words = 1 + REG_TYPE_COUNT + D;
  uint32_t cave_tables = 0, rw_tables = 0;
  for (size_t ti = 0; ti < t->ntables; ++ti)
  {
    cave_tables += t->tables[ti].place == NAM_PLACE_CAVE;
    rw_tables += t->tables[ti].place == NAM_PLACE_RW_TAIL;
  }
  const uint32_t new_tab_bytes = (REG_NAME_COUNT + D) * 4;
  uint32_t hook_bytes = (uint32_t)sizeof(k_cat_hook) + 8u + 4u * npairs + hook_names; /* hook + 2 lists */
  uint32_t cave_total = types_words * 4 + 2 * new_tab_bytes + cave_tables * new_tab_bytes + str_bytes + hook_bytes;
  uint32_t cave_off, cave_vaddr, rw_off = 0, rw_vaddr = 0;
  if (!cave_alloc(data, data_len, cave_total, &cave_off, &cave_vaddr, err, err_size))
    return false;
  if (rw_tables && !rw_tail_alloc(data, data_len, rw_tables * new_tab_bytes, &rw_off, &rw_vaddr, err, err_size))
    return false;

  uint32_t o = cave_off, v = cave_vaddr;
  uint32_t t_off = o, t_vaddr = v;
  o += types_words * 4;
  v += types_words * 4;
  uint32_t n_off = o, n_vaddr = v;
  o += new_tab_bytes;
  v += new_tab_bytes;
  uint32_t h_off = o, h_vaddr = v;
  o += new_tab_bytes;
  v += new_tab_bytes;
  uint32_t s_off = o, s_vaddr = v; /* strings go last, after the cave tables */
  o += str_bytes;
  v += str_bytes;
  o = (o + 3u) & ~3u;
  v = (v + 3u) & ~3u;

  /* ---- 3. strings: p_name[id] / p_short[id] for every extra id (names are "<n>", "<n> 2", "<n> 3", ...) ---- */
  uint32_t p_name[NAM_MAX_IDS], p_short[NAM_MAX_IDS];
  {
    uint32_t so = s_off, sv = s_vaddr, id = 0;
    for (uint32_t p = 0; p < npairs; ++p)
    {
      size_t nl = strlen(pairs[p].name), sl = strlen(pairs[p].short_name);
      uint32_t inst = nam_pair_instances(&pairs[p]);
      for (uint32_t k = 0; k < inst; ++k, ++id)
      {
        p_name[id] = sv;
        memcpy(data + so, pairs[p].name, nl);
        size_t add = k ? (size_t)snprintf((char*)data + so + nl, 4, " %u", (unsigned)(k + 1)) : 0;
        data[so + nl + add] = 0;
        so += (uint32_t)(nl + add + 1), sv += (uint32_t)(nl + add + 1);
        p_short[id] = sv;
        memcpy(data + so, pairs[p].short_name, sl);
        add = k ? (size_t)snprintf((char*)data + so + sl, 4, " %u", (unsigned)(k + 1)) : 0;
        data[so + sl + add] = 0;
        so += (uint32_t)(sl + add + 1), sv += (uint32_t)(sl + add + 1);
      }
    }
  }

  /* ---- 4. types array: header word + 166 entries + the new pairs ---- */
  memcpy(data + t_off, data + (t->types_start - VADDR_BASE), (1 + REG_TYPE_COUNT) * 4);
  for (uint32_t p = 0, id = 0; p < npairs; ++p)
    for (uint32_t k = 0; k < nam_pair_instances(&pairs[p]); ++k, ++id)
      wr32(data, t_off + (1 + REG_TYPE_COUNT + id) * 4, pairs[p].type_idx);
  wr32(data, t->types_start_lit - VADDR_BASE, t_vaddr);
  wr32(data, t->types_end_lit - VADDR_BASE, t_vaddr + (REG_TYPE_COUNT + D) * 4);

  /* ---- 5. names + short names: [0..166], new pairs, then FX-Loop last ---- */
  const uint32_t dst[2] = {n_off, h_off}, srcv[2] = {t->names_base, t->short_base};
  for (int i = 0; i < 2; ++i)
  {
    uint32_t src = srcv[i] - VADDR_BASE;
    for (uint32_t k = 0; k < REG_NAME_COUNT - 1; ++k)
      wr32(data, dst[i] + k * 4, rd32(data, src + k * 4));
    for (uint32_t id = 0; id < D; ++id)
      wr32(data, dst[i] + (REG_NAME_COUNT - 1 + id) * 4, i == 0 ? p_name[id] : p_short[id]);
    wr32(data, dst[i] + (REG_NAME_COUNT - 1 + D) * 4, rd32(data, src + (REG_NAME_COUNT - 1) * 4));
  }
  wr32(data, t->names_lit_ctor - VADDR_BASE, n_vaddr - 4);
  wr32(data, t->names_lit_map - VADDR_BASE, n_vaddr - 4);
  for (size_t i = 0; i < NAM_MAX_NAME_READERS && t->names16_lits[i]; ++i)
    wr32(data, t->names16_lits[i] - VADDR_BASE, n_vaddr + 16);
  for (size_t i = 0; i < NAM_MAX_NAME_READERS && t->names_movw[i]; ++i)
    if (!patch_movw_movt(data, data_len, t->names_movw[i], t->names_base, n_vaddr, err, err_size))
      return false;
  if (!patch_movw_movt(data, data_len, t->short_movw, t->short_base, h_vaddr, err, err_size))
    return false;

  /* ---- 6. the other id-indexed tables. Cave/RW tables first, then the in-place ones (which overwrite the first
   *         entries of the old name / short-name arrays, already copied above). ---- */
  uint32_t next_cave_off = (s_off + str_bytes + 3u) & ~3u, next_cave_vaddr = (s_vaddr + str_bytes + 3u) & ~3u;
  uint32_t next_rw_off = rw_off, next_rw_vaddr = rw_vaddr;
  for (int pass = 0; pass < 2; ++pass)
  {
    for (size_t ti = 0; ti < t->ntables; ++ti)
    {
      const NamIdTable* T = &t->tables[ti];
      if ((pass == 0) == (T->place == NAM_PLACE_IN_PLACE))
        continue;
      uint32_t old_off = T->base - VADDR_BASE;
      if (T->place == NAM_PLACE_IN_PLACE)
      {
        extend_table(data, old_off, old_off, D);
        continue;
      }
      uint32_t d_off, d_vaddr;
      if (T->place == NAM_PLACE_CAVE)
      {
        d_off = next_cave_off, d_vaddr = next_cave_vaddr;
        next_cave_off += new_tab_bytes, next_cave_vaddr += new_tab_bytes;
      }
      else
      {
        d_off = next_rw_off, d_vaddr = next_rw_vaddr;
        next_rw_off += new_tab_bytes, next_rw_vaddr += new_tab_bytes;
      }
      extend_table(data, old_off, d_off, D);
      for (int s = 0; s < 2 && T->sites[s]; ++s)
        if (!patch_movw_movt(data, data_len, T->sites[s], T->base, d_vaddr, err, err_size))
          return false;
    }
  }

  /* ---- 6b. picker catalog: append the pair names to the Distortion / Reverb lists ---- */
  {
    uint32_t h_o = next_cave_off, h_v = next_cave_vaddr;
    memcpy(data + h_o, k_cat_hook, sizeof(k_cat_hook));
    wr32(data, h_o + CAT_HOOK_LIT_OFF, t->cat_str_range_ctor);
    wr32(data, h_o + CAT_HOOK_LIT_OFF + 4, t->cat_str_cstr_ctor);
    wr32(data, h_o + CAT_HOOK_LIT_OFF + 8, t->cat_vec_build);
    uint32_t cur_o = h_o + (uint32_t)sizeof(k_cat_hook), cur_v = h_v + (uint32_t)sizeof(k_cat_hook);
    const struct
    {
      uint32_t category, call_site, veneer;
    } cats[2] = {{NAM_CAT_DISTORTION, t->cat_call_site, t->cat_veneer}, {NAM_CAT_REVERB, t->cat2_call_site, t->cat2_veneer}};
    for (int c = 0; c < 2; ++c)
    {
      uint32_t n = 0;
      for (uint32_t p = 0; p < npairs; ++p)
        n += pairs[p].category == cats[c].category;
      if (n == 0)
        continue; /* nothing to add: leave that category's call site alone */
      uint32_t l_o = cur_o, l_v = cur_v;
      uint32_t n_o = l_o + 4 + 4 * n, n_v = l_v + 4 + 4 * n, k = 0;
      wr32(data, l_o, n); /* extra names */
      for (uint32_t p = 0; p < npairs; ++p)
      {
        if (pairs[p].category != cats[c].category)
          continue;
        size_t nl = strlen(pairs[p].name);
        wr32(data, l_o + 4 + 4 * k++, n_v);
        memcpy(data + n_o, pairs[p].name, nl + 1);
        uint32_t adv = (uint32_t)((nl + 1 + 3) & ~3u);
        n_o += adv, n_v += adv;
      }
      cur_o = n_o, cur_v = n_v;
      /* veneer: ldr r3,[pc] (list) ; ldr pc,[pc] (hook) ; .word list ; .word hook */
      uint32_t vo = cats[c].veneer - VADDR_BASE;
      wr32(data, vo + 0, 0xe59f3000u);
      wr32(data, vo + 4, 0xe59ff000u);
      wr32(data, vo + 8, l_v);
      wr32(data, vo + 12, h_v);
      int32_t rel = ((int32_t)cats[c].veneer - (int32_t)(cats[c].call_site + 8)) >> 2;
      wr32(data, cats[c].call_site - VADDR_BASE, 0xeb000000u | ((uint32_t)rel & 0xffffffu));
    }
  }

  /* ---- 7. bounds and hard-coded ids ---- */
  struct
  {
    uint32_t vaddr, old_w, add;
  } bumps[] = {
      {t->map_end_insn, t->map_end_insn_old, 4 * D},
      {t->short_loop_cmp, t->short_loop_cmp_old, D},
      {t->cmp_last_idx, t->cmp_last_idx_old, D},
      {t->cmp_count, t->cmp_count_old, D},
      {t->memset_sz, t->memset_sz_old, 4 * D},
  };
  for (size_t i = 0; i < sizeof(bumps) / sizeof(bumps[0]); ++i)
  {
    uint32_t w = bump_imm(bumps[i].old_w, bumps[i].add);
    if (!w)
    {
      set_err(err, err_size, "bound @ 0x%x cannot be encoded for %u pairs", (unsigned)bumps[i].vaddr, (unsigned)npairs);
      return false;
    }
    wr32(data, bumps[i].vaddr - VADDR_BASE, w);
  }
  for (size_t i = 0; i < t->n_id_sites; ++i)
  {
    uint32_t add = id_site_add(t->id_sites[i].kind, D, R);
    wr32(data, t->id_sites[i].vaddr - VADDR_BASE, bump_imm(t->id_sites[i].old_w, add));
  }
  if (D > 4) /* the 4-id build stays byte-identical to the one confirmed on hardware */
  {
    const uint32_t wa = bump_imm(t->statemap_new_a_old, 16 * D), wb = bump_imm(t->statemap_new_b_old, 16 * D);
    if (!wa || !wb)
    {
      set_err(err, err_size, "StateMap allocation size cannot be encoded for %u ids", (unsigned)D);
      return false;
    }
    wr32(data, t->statemap_new_a - VADDR_BASE, wa);
    wr32(data, t->statemap_new_b - VADDR_BASE, wb);
  }
  return true;
}

bool nam_elf_patch_registry_test(const SpyTarget* t, uint8_t* data, size_t data_len, const char* name,
                                 const char* short_name, uint32_t type_idx, char* err, size_t err_size)
{
  NamPair p = {name, short_name, type_idx};
  return nam_elf_patch_registry(t, data, data_len, &p, 1, err, err_size);
}

/* ---- property-node registration for the extra pairs ----------------------------------------------------------
 *
 * The StateMap builder (fcn 0x5f88a8) creates every pedal's property node by code: FUN_00594ab4(this, name, storage,
 * descriptors, nParams, id), later FUN_005938bc(storage, descriptors, "/Engine/MixerCtrl/", "/Engine/MixerCtrl2/",
 * "<Name>/") to link them to the engine's parameters, and finally FUN_00406014(this, a, b) which walks a hard-coded
 * list of every pedal's storage (FUN_005b3654) to connect each property to its value source. A pair added only
 * through the name tables has none of this: no node (crash on save), then no links, then no value source (a
 * transparent pedal with dead knobs). Three hooks fix that for ids 167.. with Glorious Drive's descriptors (the pairs
 * are built as that type):
 *  A - the Glorious Drive 2 node call (0x5fd3b8) runs the original, then registers every extra instance;
 *  B - the Glorious Drive path-link call (0x6041fc) runs the original, then links every extra instance;
 *  C - the entry of 0x406014 (two displaced instructions) activates the extra storages first.
 * A and B are reached through veneers in dead code (the calls are out of bl range of the cave); the hooks themselves
 * live in the dead original types array. Per instance (storage, name, path name) triples follow the hook code; the
 * storages are private zeroed 12-byte vectors in the R+W tail. */
#define ENG_TAB_MAX 8u
/* engine table: count + n x {engine ptr, name QString ptr}; n = 8 (what the engine stub's `cmp r2,#8` allows), or the
 * id count when that is above 4 (6 ids): the R+W tail slack cannot hold more, and the stub's limit is patched to n */
static uint32_t eng_tab_entries(uint32_t ids)
{
  return ids > 4u ? ids : ENG_TAB_MAX;
}
#define ENG_TAB_BYTES(ids) (4u + 8u * eng_tab_entries(ids))
#define NODE_HOOK_B_OFF 0xa8u
#define NODE_HOOK_C_OFF 0x164u
#define NODE_HOOK_D_OFF 0x1e8u
#define NODE_HOOK_TAB_OFF 0x244u
/* Evil addresses baked into k_node_hooks (assembled against the Pedalboard): {blob offset, Pedalboard value}; they are
 * rewritten with the target's own at install time */
#define NODE_LIT_C_RESUME 0x1e4u /* activate_all + 8 */
#define NODE_LIT_D_FN 0x238u     /* picker_fn */
#define NODE_LIT_D_OK 0x23cu     /* picker_ok */
#define NODE_LIT_D_FAIL 0x240u   /* picker_exit + 8 */

static const uint8_t k_node_hooks[616] = {
  0xf0, 0x47, 0x2d, 0xe9, 0x00, 0x80, 0xa0, 0xe1, 0x20, 0x40, 0x9d, 0xe5,
  0x24, 0x50, 0x9d, 0xe5, 0x08, 0xd0, 0x4d, 0xe2, 0x00, 0x40, 0x8d, 0xe5,
  0x04, 0x50, 0x8d, 0xe5, 0x88, 0x9f, 0x8f, 0xe2, 0x00, 0xc0, 0x99, 0xe5,
  0x3c, 0xff, 0x2f, 0xe1, 0x08, 0xd0, 0x8d, 0xe2, 0x20, 0xd0, 0x4d, 0xe2,
  0x08, 0x60, 0x8d, 0xe2, 0x24, 0xa0, 0x89, 0xe2, 0x00, 0x70, 0xa0, 0xe3,
  0x08, 0x00, 0x86, 0xe2, 0x00, 0x00, 0x86, 0xe5, 0x06, 0x00, 0xa0, 0xe1,
  0x04, 0x10, 0x9a, 0xe5, 0x04, 0xc0, 0x99, 0xe5, 0x3c, 0xff, 0x2f, 0xe1,
  0x00, 0x20, 0x9a, 0xe5, 0x00, 0x30, 0xa0, 0xe3, 0x00, 0x30, 0x82, 0xe5,
  0x04, 0x30, 0x82, 0xe5, 0x08, 0x30, 0x82, 0xe5, 0x08, 0x00, 0xa0, 0xe1,
  0x06, 0x10, 0xa0, 0xe1, 0x0c, 0x30, 0x99, 0xe5, 0x07, 0x40, 0xa0, 0xe3,
  0x00, 0x40, 0x8d, 0xe5, 0xa7, 0x40, 0x87, 0xe2, 0x04, 0x40, 0x8d, 0xe5,
  0x00, 0xc0, 0x99, 0xe5, 0x3c, 0xff, 0x2f, 0xe1, 0x0c, 0xa0, 0x8a, 0xe2,
  0x01, 0x70, 0x87, 0xe2, 0x14, 0x30, 0x99, 0xe5, 0x03, 0x00, 0x57, 0xe1,
  0xe6, 0xff, 0xff, 0xba, 0x20, 0xd0, 0x8d, 0xe2, 0xf0, 0x87, 0xbd, 0xe8,
  0xf0, 0x47, 0x2d, 0xe9, 0x20, 0x50, 0x9d, 0xe5, 0x08, 0xd0, 0x4d, 0xe2,
  0x00, 0x50, 0x8d, 0xe5, 0x61, 0x9f, 0x8f, 0xe2, 0x08, 0xc0, 0x99, 0xe5,
  0x3c, 0xff, 0x2f, 0xe1, 0x08, 0xd0, 0x8d, 0xe2, 0x50, 0xd0, 0x4d, 0xe2,
  0x24, 0xa0, 0x89, 0xe2, 0x00, 0x70, 0xa0, 0xe3, 0x08, 0x60, 0x8d, 0xe2,
  0x08, 0x00, 0x86, 0xe2, 0x00, 0x00, 0x86, 0xe5, 0x06, 0x00, 0xa0, 0xe1,
  0x18, 0x10, 0x99, 0xe5, 0x04, 0xc0, 0x99, 0xe5, 0x3c, 0xff, 0x2f, 0xe1,
  0x20, 0x60, 0x8d, 0xe2, 0x08, 0x00, 0x86, 0xe2, 0x00, 0x00, 0x86, 0xe5,
  0x06, 0x00, 0xa0, 0xe1, 0x1c, 0x10, 0x99, 0xe5, 0x04, 0xc0, 0x99, 0xe5,
  0x3c, 0xff, 0x2f, 0xe1, 0x38, 0x60, 0x8d, 0xe2, 0x08, 0x00, 0x86, 0xe2,
  0x00, 0x00, 0x86, 0xe5, 0x06, 0x00, 0xa0, 0xe1, 0x08, 0x10, 0x9a, 0xe5,
  0x04, 0xc0, 0x99, 0xe5, 0x3c, 0xff, 0x2f, 0xe1, 0x00, 0x00, 0x9a, 0xe5,
  0x0c, 0x10, 0x99, 0xe5, 0x08, 0x20, 0x8d, 0xe2, 0x20, 0x30, 0x8d, 0xe2,
  0x38, 0x40, 0x8d, 0xe2, 0x00, 0x40, 0x8d, 0xe5, 0x08, 0xc0, 0x99, 0xe5,
  0x3c, 0xff, 0x2f, 0xe1, 0x0c, 0xa0, 0x8a, 0xe2, 0x01, 0x70, 0x87, 0xe2,
  0x14, 0x30, 0x99, 0xe5, 0x03, 0x00, 0x57, 0xe1, 0xdd, 0xff, 0xff, 0xba,
  0x50, 0xd0, 0x8d, 0xe2, 0xf0, 0x87, 0xbd, 0xe8, 0xf7, 0x40, 0x2d, 0xe9,
  0x01, 0x40, 0xa0, 0xe1, 0x02, 0x50, 0xa0, 0xe1, 0x33, 0x6f, 0x8f, 0xe2,
  0x24, 0x30, 0x86, 0xe2, 0x00, 0x70, 0xa0, 0xe3, 0x00, 0x00, 0x93, 0xe5,
  0x04, 0x10, 0xa0, 0xe1, 0x05, 0x20, 0xa0, 0xe1, 0x10, 0xc0, 0x96, 0xe5,
  0x04, 0x30, 0x2d, 0xe5, 0x04, 0xd0, 0x4d, 0xe2, 0x3c, 0xff, 0x2f, 0xe1,
  0x04, 0xd0, 0x8d, 0xe2, 0x04, 0x30, 0x9d, 0xe4, 0x0c, 0x30, 0x83, 0xe2,
  0x01, 0x70, 0x87, 0xe2, 0x14, 0x00, 0x96, 0xe5, 0x00, 0x00, 0x57, 0xe1,
  0xf1, 0xff, 0xff, 0xba, 0x20, 0x00, 0x96, 0xe5, 0x00, 0xc0, 0x90, 0xe5,
  0x00, 0x00, 0x5c, 0xe3, 0x03, 0x00, 0x00, 0x0a, 0x24, 0x00, 0x86, 0xe2,
  0x14, 0x10, 0x96, 0xe5, 0x00, 0x20, 0x9d, 0xe5, 0x3c, 0xff, 0x2f, 0xe1,
  0xf7, 0x40, 0xbd, 0xe8, 0xf8, 0x41, 0x6d, 0xe1, 0x01, 0x40, 0xa0, 0xe1,
  0x04, 0xf0, 0x1f, 0xe5, 0x1c, 0x60, 0x40, 0x00, 0xa7, 0x30, 0x46, 0xe2,
  0x03, 0x00, 0x53, 0xe3, 0x0d, 0x00, 0x00, 0x2a, 0x01, 0x60, 0x86, 0xe2,
  0x04, 0x00, 0xa0, 0xe1, 0x06, 0x10, 0xa0, 0xe1, 0x30, 0xc0, 0x9f, 0xe5,
  0x3c, 0xff, 0x2f, 0xe1, 0x00, 0x30, 0xe0, 0xe1, 0xa3, 0x3f, 0xa0, 0xe1,
  0x05, 0x00, 0x50, 0xe1, 0x00, 0x30, 0xa0, 0x03, 0x00, 0x00, 0x53, 0xe3,
  0x18, 0xf0, 0x9f, 0x05, 0xa7, 0x30, 0x46, 0xe2, 0x03, 0x00, 0x53, 0xe3,
  0xf1, 0xff, 0xff, 0x3a, 0x08, 0x10, 0xa0, 0xe1, 0x38, 0x00, 0x8d, 0xe2,
  0x04, 0xf0, 0x9f, 0xe5, 0x74, 0xce, 0x3c, 0x00, 0x44, 0xdd, 0x3c, 0x00,
  0xe8, 0xdf, 0x3c, 0x00, 0xb4, 0x4a, 0x59, 0x00, 0x84, 0x2e, 0x5b, 0x00,
  0xbc, 0x38, 0x59, 0x00, 0x44, 0xa2, 0x3c, 0x03, 0x54, 0x36, 0x5b, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
};

bool nam_elf_patch_node_registration(const SpyTarget* t, uint8_t* data, size_t data_len, const NamPair* pairs,
                                     uint32_t npairs, uint32_t* out_init_slot, uint32_t* out_eng_tab, char* err,
                                     size_t err_size)
{
  uint32_t inst = 0;
  if (!nam_pairs_ids(pairs, npairs, &inst, err, err_size))
    return false;
  if (!check_word(data, data_len, t->node_call_a, t->node_call_a_w, "Glorious Drive 2 node call", err, err_size)
      || !check_word(data, data_len, t->node_call_b, t->node_call_b_w, "Glorious Drive path call", err, err_size)
      || !check_word(data, data_len, t->node_veneer_a, t->node_veneer_a_w, "dead veneer A", err, err_size)
      || !check_word(data, data_len, t->node_veneer_b, t->node_veneer_b_w, "dead veneer B", err, err_size)
      || !check_word(data, data_len, t->activate_all, t->activate_all_w0, "activate-all entry", err, err_size)
      || !check_word(data, data_len, t->activate_all + 4, t->activate_all_w1, "activate-all entry+4", err, err_size))
    return false;
  /* the hook C code re-executes the two displaced instructions itself: they must be the ones it was assembled with */
  if (t->activate_all_w0 != 0xe16d41f8u || t->activate_all_w1 != 0xe1a04001u)
  {
    set_err(err, err_size, "REFUSING: activate-all entry differs from the one hook C replays");
    return false;
  }
  const uint32_t region = (1u + REG_TYPE_COUNT) * 4u;
  const uint32_t blob_len = (uint32_t)sizeof(k_node_hooks);
  /* The {storage, name, path} triples normally follow the blob inside the old types array. Past 4 ids they no longer
   * fit (3 pairs = 6 ids): then they go to the R+W tail and the four `add rX, rY, #0x24` that formed their address
   * (tab + 0x24) become `ldr rX, [rY, #0x24]` reading a pointer stored there instead. */
  const bool relocate = blob_len + 12u * inst > region;
  if (relocate && blob_len + 4u > region)
  {
    set_err(err, err_size, "REFUSING: node hooks do not fit the old types array");
    return false;
  }
  static const struct
  {
    uint32_t off, add_word, ldr_word;
  } k_triple_sites[4] = {{0x34u, 0xe289a024u, 0xe599a024u},
                         {0xccu, 0xe289a024u, 0xe599a024u},
                         {0x174u, 0xe2863024u, 0xe5963024u},
                         {0x1c4u, 0xe2860024u, 0xe5960024u}};
  for (int i = 0; i < 4; ++i)
  {
    uint32_t w;
    memcpy(&w, k_node_hooks + k_triple_sites[i].off, 4);
    if (w != k_triple_sites[i].add_word)
    {
      set_err(err, err_size, "internal error: node hook blob does not have the expected triple-address instructions");
      return false;
    }
  }
  if (rd32(data, t->types_start_lit - VADDR_BASE) == t->types_start)
  {
    set_err(err, err_size, "REFUSING: registry patch must run first (old types array still in use)");
    return false;
  }
  /* storages (writable) go in the R+W tail; the strings are read-only and fit the dead original name array, past the
   * entries the in-place category-table extension overwrites */
  static const char k_p1[] = "/Engine/MixerCtrl/", k_p2[] = "/Engine/MixerCtrl2/";
  uint32_t str_bytes = (uint32_t)(sizeof(k_p1) + sizeof(k_p2) + 8);
  for (uint32_t p = 0; p < npairs; ++p)
    str_bytes += nam_pair_instances(&pairs[p]) * (uint32_t)((strlen(pairs[p].name) + 8 + 3) & ~3u) * 2u;
  uint32_t str_start = t->names_base + 4u * inst + 8u;
  if (rd32(data, t->names_lit_ctor - VADDR_BASE) == t->names_base - 4)
  {
    set_err(err, err_size, "REFUSING: node strings do not fit the old name array, or the registry patch has not run");
    return false;
  }
  bool strings_in_cave = false;
  uint32_t cave_str_off = 0;
  if (str_start + str_bytes > t->names_base + 0xf8u /* the engine vtable clone starts at +0x100 */)
  {
    /* too many / too long names for the dead name array: the strings (read-only data) go to the code cave */
    if (!cave_alloc(data, data_len, str_bytes, &cave_str_off, &str_start, err, err_size))
      return false;
    strings_in_cave = true;
  }
  uint32_t r_off, r_vaddr;
  /* storages, then the init-hook slot (one word, read by hook C) and the engine table the engine stub fills
   * ({count, 8 x {engine, &name}}) */
  if (!rw_tail_alloc(data, data_len, 12u * inst + 4u + ENG_TAB_BYTES(inst), &r_off, &r_vaddr, err, err_size))
    return false;
  uint32_t triples_off = 0, triples_vaddr = 0; /* only used when relocate: the (read-only) triples go to the cave */
  if (relocate && !cave_alloc(data, data_len, 12u * inst, &triples_off, &triples_vaddr, err, err_size))
    return false;
  const uint32_t c_off = t->types_start - VADDR_BASE, c_vaddr = t->types_start;
  memset(data + c_off, 0, region);
  memcpy(data + c_off, k_node_hooks, blob_len);
  const uint32_t tab = c_off + NODE_HOOK_TAB_OFF;
  {
    static const struct
    {
      uint32_t off, pb;
    } lits[] = {{NODE_LIT_C_RESUME, 0x40601cu}, {NODE_LIT_D_FN, 0x3cce74u}, {NODE_LIT_D_OK, 0x3cdd44u},
                {NODE_LIT_D_FAIL, 0x3cdfe8u},   {NODE_HOOK_TAB_OFF, 0x594ab4u},  {NODE_HOOK_TAB_OFF + 4, 0x5b2e84u},
                {NODE_HOOK_TAB_OFF + 8, 0x5938bcu}, {NODE_HOOK_TAB_OFF + 12, 0x33ca244u},
                {NODE_HOOK_TAB_OFF + 16, 0x5b3654u}};
    const uint32_t val[] = {t->activate_all + 8, t->picker_fn, t->picker_ok, t->picker_exit + 8, t->node_fn,
                            t->cat_str_cstr_ctor, t->link_fn, t->gd_desc, t->activate_fn};
    for (size_t k = 0; k < sizeof(lits) / sizeof(lits[0]); ++k)
    {
      if (rd32(data, c_off + lits[k].off) != lits[k].pb)
      {
        set_err(err, err_size, "internal error: node hook literal at +0x%x is not the assembled one", (unsigned)lits[k].off);
        return false;
      }
      wr32(data, c_off + lits[k].off, val[k]);
    }
  }
  uint32_t so = strings_in_cave ? cave_str_off : str_start - VADDR_BASE, sv = str_start;
#define NODE_STR(text, out_v)                                                                                        \
  do                                                                                                                 \
  {                                                                                                                  \
    const char* s_ = (text);                                                                                         \
    size_t l_ = strlen(s_) + 1;                                                                                      \
    memcpy(data + so, s_, l_);                                                                                       \
    (out_v) = sv;                                                                                                    \
    so += (uint32_t)((l_ + 3u) & ~3u);                                                                               \
    sv += (uint32_t)((l_ + 3u) & ~3u);                                                                               \
  } while (0)
  uint32_t v_p1, v_p2;
  NODE_STR(k_p1, v_p1);
  NODE_STR(k_p2, v_p2);
  const uint32_t init_slot = r_vaddr + 12u * inst;
  wr32(data, tab + 20, inst);
  wr32(data, tab + 32, init_slot);
  wr32(data, tab + 24, v_p1);
  wr32(data, tab + 28, v_p2);
  uint32_t i = 0;
  for (uint32_t p = 0; p < npairs; ++p)
    for (uint32_t k = 0; k < nam_pair_instances(&pairs[p]); ++k, ++i)
    {
      char nm[40], pn[48];
      if (k)
        snprintf(nm, sizeof(nm), "%s %u", pairs[p].name, (unsigned)(k + 1));
      else
        snprintf(nm, sizeof(nm), "%s", pairs[p].name);
      snprintf(pn, sizeof(pn), "%s/", nm);
      uint32_t v_name, v_path;
      NODE_STR(nm, v_name);
      NODE_STR(pn, v_path);
      uint32_t trip = relocate ? triples_off + 12 * i : tab + 36 + 12 * i;
      wr32(data, trip, r_vaddr + 12 * i);
      wr32(data, trip + 4, v_name);
      wr32(data, trip + 8, v_path);
    }
#undef NODE_STR
  if (relocate)
  {
    wr32(data, tab + 36, triples_vaddr);
    for (int k = 0; k < 4; ++k)
      wr32(data, c_off + k_triple_sites[k].off, k_triple_sites[k].ldr_word);
  }
  /* hook D: a 4-instance pedal tries ids first+2 and first+3 when the picker finds the first two in use. The
   * displaced pair (picker_exit) is the picker's "both instances in use" exit. It goes in whenever there are 4 extra
   * ids, so the shipped two-pair Pedalboard build has it too (as confirmed on hardware). Targets without it
   * (picker_exit = 0: MX5, Gigboard) keep the stock picker, which refuses a third "NAM" when two are in use; a single
   * 4-instance pedal is refused there. */
  if (inst == 4 && !t->picker_exit)
  {
    for (uint32_t p = 0; p < npairs; ++p)
      if (nam_pair_instances(&pairs[p]) == 4)
      {
        set_err(err, err_size, "4-instance pedals are not supported on the %s", t->model);
        return false;
      }
  }
  else if (inst == 4)
  {
    if (!check_word(data, data_len, t->picker_exit, t->picker_exit_w0, "picker exit", err, err_size)
        || !check_word(data, data_len, t->picker_exit + 4, t->picker_exit_w1, "picker exit+4", err, err_size))
      return false;
    if (t->picker_exit_w0 != 0xe1a01008u || t->picker_exit_w1 != 0xe28d0038u) /* hook D replays them */
    {
      set_err(err, err_size, "REFUSING: picker exit differs from the one hook D replays");
      return false;
    }
    wr32(data, t->picker_exit - VADDR_BASE, 0xe51ff004u);
    wr32(data, t->picker_exit + 4 - VADDR_BASE, c_vaddr + NODE_HOOK_D_OFF);
  }
  /* hook C: displaced entry of 0x406014 */
  wr32(data, t->activate_all - VADDR_BASE, 0xe51ff004u);
  wr32(data, t->activate_all + 4 - VADDR_BASE, c_vaddr + NODE_HOOK_C_OFF);
  /* veneers A/B: ldr pc,[pc,#-4] ; .word hook */
  wr32(data, t->node_veneer_a - VADDR_BASE, 0xe51ff004u);
  wr32(data, t->node_veneer_a - VADDR_BASE + 4, c_vaddr);
  wr32(data, t->node_veneer_b - VADDR_BASE, 0xe51ff004u);
  wr32(data, t->node_veneer_b - VADDR_BASE + 4, c_vaddr + NODE_HOOK_B_OFF);
  wr32(data, t->node_call_a - VADDR_BASE,
       0xeb000000u | ((uint32_t)(((int32_t)t->node_veneer_a - (int32_t)(t->node_call_a + 8)) >> 2) & 0xffffffu));
  wr32(data, t->node_call_b - VADDR_BASE,
       0xeb000000u | ((uint32_t)(((int32_t)t->node_veneer_b - (int32_t)(t->node_call_b + 8)) >> 2) & 0xffffffu));
  if (out_init_slot)
    *out_init_slot = init_slot;
  if (out_eng_tab)
    *out_eng_tab = init_slot + 4u;
  return true;
}

/* ---- own audio engine for the extra pedals ------------------------------------------------------------------
 *
 * Extra pedals built as Glorious Drive would share that pedal's engine class (vtable 0x1828f44, process() slot 8 =
 * 0x2c6b68). To run NAM only in the extra pedals, they get their own copies of both vtables:
 *  - ModFac_construct's dead case for type 80 is turned into a Glorious-Drive-shaped constructor (its two literals are
 *    repointed: Glorious Drive's VTT, module vtable = a clone of Glorious Drive's), so the registry builds the extra
 *    pedals as type 80 (Pedalboard addresses: VTT 0x182314c, module vtable 0x1824588);
 *  - the module vtable clone's setup slot (19, 0x27cc20) points at a stub that runs the original setup (which creates
 *    the engine at module+0x270) and then repoints the engine's vtable at a clone of 0x1828f44 whose process() slot
 *    is a trampoline: it jumps through a writable hook slot that libnam_preload.so fills in at run time, else falls
 *    back to the real process().
 * The vtable clones and the stub live in the dead original short-name array (the module side) and name array (the
 * engine side); the hook slot is one word of the R+W tail. */
#define ENG_TYPE 80u
#define ENG_MOD_VT_WORDS 64u
#define ENG_SETUP_SLOT 19u
#define ENG_VT_WORDS 72u
#define ENG_PROCESS_SLOT 8u
/* the stubs' literals for the original setup() / process() (assembled with the Pedalboard's 0x27cc20 / 0x2c6b68) */
#define ENG_STUB_LIT_SETUP_OFF 0x80u
#define ENG_STUB_LIT_PROC_OFF 0x8cu
#define ENG_STUBR_LIT_SETUP_OFF 0x6cu
#define ENG_STUBR_LIT_PROC_OFF 0x78u
#define ENG_STUB_SETUP_OFF 0x00u
#define ENG_STUB_TRAMP_OFF 0x6cu
#define ENG_STUB_LIT_EVT_OFF 0x84u
#define ENG_STUB_LIT_SLOT_OFF 0x88u
#define ENG_STUB_LIT_TAB_OFF 0x90u
#define ENG_STUB_CMP_OFF 0x44u /* cmp r2, #8 (table capacity) */

static const uint8_t k_eng_stub[148] = {
  0x70, 0x40, 0x2d, 0xe9, 0x10, 0xc0, 0x9d, 0xe5, 0x08, 0xd0, 0x4d, 0xe2,
  0x00, 0xc0, 0x8d, 0xe5, 0x00, 0x40, 0xa0, 0xe1, 0x02, 0x60, 0xa0, 0xe1,
  0x60, 0xc0, 0x9f, 0xe5, 0x3c, 0xff, 0x2f, 0xe1, 0x08, 0xd0, 0x8d, 0xe2,
  0x00, 0x50, 0xa0, 0xe1, 0x70, 0x02, 0x94, 0xe5, 0x00, 0x00, 0x50, 0xe3,
  0x0b, 0x00, 0x00, 0x0a, 0x48, 0x10, 0x9f, 0xe5, 0x00, 0x10, 0x80, 0xe5,
  0x4c, 0x10, 0x9f, 0xe5, 0x00, 0x20, 0x91, 0xe5, 0x08, 0x00, 0x52, 0xe3,
  0x05, 0x00, 0x00, 0x2a, 0x04, 0x30, 0x81, 0xe2, 0x82, 0x31, 0x83, 0xe0,
  0x00, 0x00, 0x83, 0xe5, 0x04, 0x60, 0x83, 0xe5, 0x01, 0x20, 0x82, 0xe2,
  0x00, 0x20, 0x81, 0xe5, 0x05, 0x00, 0xa0, 0xe1, 0x70, 0x80, 0xbd, 0xe8,
  0x14, 0xc0, 0x9f, 0xe5, 0x00, 0xc0, 0x9c, 0xe5, 0x00, 0x00, 0x5c, 0xe3,
  0x1c, 0xff, 0x2f, 0x11, 0x08, 0xf0, 0x9f, 0xe5, 0x20, 0xcc, 0x27, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x6b, 0x2c, 0x00,
  0x00, 0x00, 0x00, 0x00,
};

/* record-hook variant (patch/engine_stub_rec.S): calls record(engine, &name) through *tab at creation instead of
 * filling the table */
#define ENG_STUBR_TRAMP_OFF 0x58u
#define ENG_STUBR_LIT_EVT_OFF 0x70u
#define ENG_STUBR_LIT_SLOT_OFF 0x74u
#define ENG_STUBR_LIT_TAB_OFF 0x7cu

static const uint8_t k_eng_stub_rec[128] = {
  0x70, 0x40, 0x2d, 0xe9, 0x10, 0xc0, 0x9d, 0xe5, 0x08, 0xd0, 0x4d, 0xe2,
  0x00, 0xc0, 0x8d, 0xe5, 0x00, 0x40, 0xa0, 0xe1, 0x02, 0x60, 0xa0, 0xe1,
  0x4c, 0xc0, 0x9f, 0xe5, 0x3c, 0xff, 0x2f, 0xe1, 0x08, 0xd0, 0x8d, 0xe2,
  0x00, 0x50, 0xa0, 0xe1, 0x70, 0x02, 0x94, 0xe5, 0x00, 0x00, 0x50, 0xe3,
  0x06, 0x00, 0x00, 0x0a, 0x34, 0x10, 0x9f, 0xe5, 0x00, 0x10, 0x80, 0xe5,
  0x38, 0xc0, 0x9f, 0xe5, 0x00, 0xc0, 0x9c, 0xe5, 0x00, 0x00, 0x5c, 0xe3,
  0x06, 0x10, 0xa0, 0x11, 0x3c, 0xff, 0x2f, 0x11, 0x05, 0x00, 0xa0, 0xe1,
  0x70, 0x80, 0xbd, 0xe8, 0x14, 0xc0, 0x9f, 0xe5, 0x00, 0xc0, 0x9c, 0xe5,
  0x00, 0x00, 0x5c, 0xe3, 0x1c, 0xff, 0x2f, 0x11, 0x08, 0xf0, 0x9f, 0xe5,
  0x20, 0xcc, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x68, 0x6b, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00,
};

bool nam_elf_patch_engine_class(const SpyTarget* t, uint8_t* data, size_t data_len, uint32_t ids, uint32_t eng_tab,
                                bool record_hook, uint32_t* out_hook_slot, char* err, size_t err_size)
{
  if (!check_word(data, data_len, t->eng_case_vtt_lit, t->eng_case_vtt_old, "dead case 80 VTT literal", err, err_size)
      || !check_word(data, data_len, t->eng_case_vt_lit, t->eng_case_vt_old, "dead case 80 vtable literal", err, err_size)
      || !check_word(data, data_len, t->eng_gd_vt_lit, t->eng_mod_vt, "Glorious Drive module vtable literal", err, err_size)
      || !check_word(data, data_len, t->eng_vt_lit, t->eng_vt, "engine vtable literal", err, err_size)
      || !check_word(data, data_len, t->eng_mod_vt + 4 * ENG_SETUP_SLOT, t->eng_setup_fn, "module setup slot", err, err_size)
      || !check_word(data, data_len, t->eng_vt + 4 * ENG_PROCESS_SLOT, t->eng_process_fn, "engine process slot", err,
                     err_size))
    return false;
  /* the registry patch must have run (it moves the old short-name / name arrays out of use) */
  if (rd32(data, t->names_lit_ctor - VADDR_BASE) == t->names_base - 4)
  {
    set_err(err, err_size, "REFUSING: registry patch must run first (old name arrays still in use)");
    return false;
  }
  /* module side: short-name array past the in-place P1 extension */
  const uint32_t mod_hdr = (t->short_base + 4u * ids + 8u + 7u) & ~7u; /* header words, 8-aligned */
  const uint32_t mod_vt = mod_hdr + 8u;
  const uint32_t stub = mod_vt + 4u * ENG_MOD_VT_WORDS;
  const uint32_t stub_end = stub + (uint32_t)sizeof(k_eng_stub);
  if (stub_end > t->short_base + REG_NAME_COUNT * 4u)
  {
    set_err(err, err_size, "REFUSING: engine stubs do not fit the old short-name array");
    return false;
  }
  /* engine side: name array, clear of the node strings (which start at +4*ids+8) */
  const uint32_t eng_hdr = t->names_base + 0x100u;
  const uint32_t eng_vt = eng_hdr + 8u;
  if (eng_vt + 4u * ENG_VT_WORDS > t->names_base + REG_NAME_COUNT * 4u)
  {
    set_err(err, err_size, "REFUSING: engine vtable does not fit the old name array");
    return false;
  }
  uint32_t slot_off, slot_vaddr;
  if (!rw_tail_alloc(data, data_len, 4, &slot_off, &slot_vaddr, err, err_size))
    return false;

  /* vtable clones: [offset-to-top, typeinfo] + entries */
  memcpy(data + (mod_hdr - VADDR_BASE), data + (t->eng_mod_vt - 8 - VADDR_BASE), 8u + 4u * ENG_MOD_VT_WORDS);
  memcpy(data + (eng_hdr - VADDR_BASE), data + (t->eng_vt - 8 - VADDR_BASE), 8u + 4u * ENG_VT_WORDS);
  /* stub + trampoline */
  uint32_t tramp_off, setup_off = ENG_STUB_SETUP_OFF;
  if (record_hook)
  {
    memcpy(data + (stub - VADDR_BASE), k_eng_stub_rec, sizeof(k_eng_stub_rec));
    wr32(data, stub - VADDR_BASE + ENG_STUBR_LIT_EVT_OFF, eng_vt);
    wr32(data, stub - VADDR_BASE + ENG_STUBR_LIT_SLOT_OFF, slot_vaddr);
    wr32(data, stub - VADDR_BASE + ENG_STUBR_LIT_TAB_OFF, eng_tab); /* *eng_tab = record hook, filled by the preload */
    tramp_off = ENG_STUBR_TRAMP_OFF;
    if (rd32(data, stub - VADDR_BASE + ENG_STUBR_LIT_SETUP_OFF) != 0x27cc20u
        || rd32(data, stub - VADDR_BASE + ENG_STUBR_LIT_PROC_OFF) != 0x2c6b68u)
    {
      set_err(err, err_size, "internal error: engine stub literals are not the assembled ones");
      return false;
    }
    wr32(data, stub - VADDR_BASE + ENG_STUBR_LIT_SETUP_OFF, t->eng_setup_fn);
    wr32(data, stub - VADDR_BASE + ENG_STUBR_LIT_PROC_OFF, t->eng_process_fn);
  }
  else
  {
    memcpy(data + (stub - VADDR_BASE), k_eng_stub, sizeof(k_eng_stub));
    if (eng_tab_entries(ids) != ENG_TAB_MAX) /* the table was sized to the id count: bound the stub's fill loop likewise */
      wr32(data, stub - VADDR_BASE + ENG_STUB_CMP_OFF, 0xe3520000u | eng_tab_entries(ids)); /* cmp r2, #n */
    wr32(data, stub - VADDR_BASE + ENG_STUB_LIT_EVT_OFF, eng_vt);
    wr32(data, stub - VADDR_BASE + ENG_STUB_LIT_SLOT_OFF, slot_vaddr);
    wr32(data, stub - VADDR_BASE + ENG_STUB_LIT_TAB_OFF, eng_tab);
    tramp_off = ENG_STUB_TRAMP_OFF;
    if (rd32(data, stub - VADDR_BASE + ENG_STUB_LIT_SETUP_OFF) != 0x27cc20u
        || rd32(data, stub - VADDR_BASE + ENG_STUB_LIT_PROC_OFF) != 0x2c6b68u)
    {
      set_err(err, err_size, "internal error: engine stub literals are not the assembled ones");
      return false;
    }
    wr32(data, stub - VADDR_BASE + ENG_STUB_LIT_SETUP_OFF, t->eng_setup_fn);
    wr32(data, stub - VADDR_BASE + ENG_STUB_LIT_PROC_OFF, t->eng_process_fn);
  }
  wr32(data, mod_vt - VADDR_BASE + 4u * ENG_SETUP_SLOT, stub + setup_off);
  wr32(data, eng_vt - VADDR_BASE + 4u * ENG_PROCESS_SLOT, stub + tramp_off);
  /* dead case 80 builds a Glorious-Drive-shaped module with the cloned vtable */
  wr32(data, t->eng_case_vtt_lit - VADDR_BASE, rd32(data, t->eng_gd_vtt_lit - VADDR_BASE));
  wr32(data, t->eng_case_vt_lit - VADDR_BASE, mod_vt);
  *out_hook_slot = slot_vaddr;
  return true;
}

/* ---- metacall spy -------------------------------------------------------------------------------------------
 *
 * fcn 0x8686c..0x87d7c is a qt_static_metacall-style dispatcher: `cmp r2,#0x30; ldrls pc,[pc,r2,lsl 2]` with the
 * (absolute) case addresses in a 49-word table at 0x867a0. Each non-trivial table word is redirected to a 20-byte
 * stub that saves r0-r3/ip/lr, loads the method index and the original target, and branches to a shared logger. The
 * logger appends {0xa5000000|index, _a, _a[1], _a[2], this, caller lr} (24 bytes) plus up to 8 bytes read from each
 * of _a[1] and _a[2] to /tmp/meta.bin using writev (a bad pointer makes writev return a short count instead of
 * faulting), stops at 1MB, restores every register and jumps to the original case through lr (dead at a case
 * entry: every case leaves through an epilogue that pops its saved lr). */
#define META_DISPATCH_CMP 0x86794u /* cmp r2, #0x30 */
#define META_DISPATCH_CMP_W 0xe3520030u
#define META_DISPATCH_JMP 0x86798u /* ldrls pc, [pc, r2, lsl 2] */
#define META_DISPATCH_JMP_W 0x979ff102u
#define META_TABLE 0x867a0u
#define META_ENTRIES 0x31u
#define META_EPILOGUE 0x8686cu /* table words pointing here are no-ops, left alone */
#define META_STUB_BYTES 20u

static const uint8_t k_meta_common[248] = {
  0xf0, 0x00, 0x2d, 0xe9, 0xa5, 0x04, 0x80, 0xe3, 0x40, 0xd0, 0x4d, 0xe2,
  0x5c, 0x50, 0x9d, 0xe5, 0x01, 0x60, 0xa0, 0xe1, 0x50, 0x40, 0x9d, 0xe5,
  0x00, 0x10, 0xa0, 0xe3, 0x00, 0x20, 0xa0, 0xe3, 0x01, 0x08, 0x55, 0xe3,
  0x03, 0x00, 0x00, 0x3a, 0x03, 0x00, 0x15, 0xe3, 0x01, 0x00, 0x00, 0x1a,
  0x04, 0x10, 0x95, 0xe5, 0x08, 0x20, 0x95, 0xe5, 0x64, 0x30, 0x9d, 0xe5,
  0x00, 0x00, 0x8d, 0xe5, 0x04, 0x50, 0x8d, 0xe5, 0x08, 0x10, 0x8d, 0xe5,
  0x0c, 0x20, 0x8d, 0xe5, 0x10, 0x40, 0x8d, 0xe5, 0x14, 0x30, 0x8d, 0xe5,
  0x0d, 0x30, 0xa0, 0xe1, 0x18, 0x30, 0x8d, 0xe5, 0x18, 0x30, 0xa0, 0xe3,
  0x1c, 0x30, 0x8d, 0xe5, 0x20, 0x10, 0x8d, 0xe5, 0x08, 0x30, 0xa0, 0xe3,
  0x24, 0x30, 0x8d, 0xe5, 0x28, 0x20, 0x8d, 0xe5, 0x2c, 0x30, 0x8d, 0xe5,
  0x68, 0x00, 0x8f, 0xe2, 0x41, 0x14, 0x00, 0xe3, 0x69, 0x2f, 0xa0, 0xe3,
  0x05, 0x70, 0xa0, 0xe3, 0x00, 0x00, 0x00, 0xef, 0x00, 0x40, 0xb0, 0xe1,
  0x0e, 0x00, 0x00, 0x4a, 0x04, 0x00, 0xa0, 0xe1, 0x00, 0x10, 0xa0, 0xe3,
  0x02, 0x20, 0xa0, 0xe3, 0x13, 0x70, 0xa0, 0xe3, 0x00, 0x00, 0x00, 0xef,
  0x01, 0x06, 0x50, 0xe3, 0x04, 0x00, 0x00, 0x2a, 0x04, 0x00, 0xa0, 0xe1,
  0x18, 0x10, 0x8d, 0xe2, 0x03, 0x20, 0xa0, 0xe3, 0x92, 0x70, 0xa0, 0xe3,
  0x00, 0x00, 0x00, 0xef, 0x04, 0x00, 0xa0, 0xe1, 0x06, 0x70, 0xa0, 0xe3,
  0x00, 0x00, 0x00, 0xef, 0x06, 0xe0, 0xa0, 0xe1, 0x40, 0xd0, 0x8d, 0xe2,
  0xf0, 0x00, 0xbd, 0xe8, 0x0f, 0x10, 0xbd, 0xe8, 0x04, 0xd0, 0x8d, 0xe2,
  0x1e, 0xff, 0x2f, 0xe1, 0x2f, 0x74, 0x6d, 0x70, 0x2f, 0x6d, 0x65, 0x74,
  0x61, 0x2e, 0x62, 0x69, 0x6e, 0x00, 0x00, 0x00,
};

bool nam_elf_patch_metacall_spy(const SpyTarget* t, uint8_t* data, size_t data_len, uint64_t method_mask, char* err,
                                size_t err_size)
{
  if (strcmp(t->model, "pedalboard") != 0)
  {
    set_err(err, err_size, "the metacall spy has no target for %s", t->model);
    return false;
  }
  if (!check_word(data, data_len, META_DISPATCH_CMP, META_DISPATCH_CMP_W, "metacall dispatch compare", err, err_size)
      || !check_word(data, data_len, META_DISPATCH_JMP, META_DISPATCH_JMP_W, "metacall dispatch jump", err, err_size))
    return false;

  uint32_t targets[META_ENTRIES];
  uint32_t n_stubs = 0;
  for (uint32_t i = 0; i < META_ENTRIES; ++i)
  {
    uint32_t tw = rd32(data, META_TABLE - VADDR_BASE + i * 4);
    if (tw < 0x86800u || tw >= 0x88000u)
    {
      set_err(err, err_size, "REFUSING: metacall table entry %u holds 0x%x (not a case address; already patched?)", i,
              (unsigned)tw);
      return false;
    }
    targets[i] = tw;
    n_stubs += (tw != META_EPILOGUE) && ((method_mask >> i) & 1u);
  }

  uint32_t need = (uint32_t)sizeof(k_meta_common) + n_stubs * META_STUB_BYTES;
  uint32_t off, vaddr;
  if (!cave_alloc(data, data_len, need, &off, &vaddr, err, err_size))
    return false;
  memcpy(data + off, k_meta_common, sizeof(k_meta_common));
  uint32_t common = vaddr;
  uint32_t so = off + (uint32_t)sizeof(k_meta_common), sv = vaddr + (uint32_t)sizeof(k_meta_common);
  for (uint32_t i = 0; i < META_ENTRIES; ++i)
  {
    if (targets[i] == META_EPILOGUE || !((method_mask >> i) & 1u))
      continue;
    int32_t rel = ((int32_t)common - (int32_t)(sv + 12 + 8)) >> 2;
    wr32(data, so + 0, 0xe92d500fu);                        /* push {r0-r3, ip, lr} */
    wr32(data, so + 4, 0xe3a00000u | i);                    /* mov r0, #i           */
    wr32(data, so + 8, 0xe59f1000u);                        /* ldr r1, [pc]  (literal at +16) */
    wr32(data, so + 12, 0xea000000u | ((uint32_t)rel & 0xffffffu)); /* b common */
    wr32(data, so + 16, targets[i]);
    wr32(data, META_TABLE - VADDR_BASE + i * 4, sv);
    so += META_STUB_BYTES;
    sv += META_STUB_BYTES;
  }
  return true;
}
