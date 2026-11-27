/* spy_patch.h -- the additive pedals' patches of /usr/Evil/Evil (registry, picker, property nodes, engine class), plus
 * two debug-only observers (ModFac_construct and the metacall dispatcher spies, Pedalboard only).
 *
 * Every address and every expected stock word these patches touch is per firmware build: they live in a SpyTarget
 * (core/spy_targets.c), one per model. The Pedalboard's was worked out by hand and is confirmed on hardware; the MX5's
 * and the Gigboard's were derived from it (same source, different builds) and are EXPERIMENTAL: built and checked
 * against the stock binaries, never run on a device. Every patch checks the stock word at each site before writing.
 */
#ifndef NAM_GUI_SPY_PATCH_H
#define NAM_GUI_SPY_PATCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* hard-coded id-space constant kinds (see k_id_sites in spy_targets.c) */
enum
{
  NAM_ID_SHIFT, /* +1 per extra id: the special ids (FX-Loop, Input, Output, Mix) and normal-range bounds */
  NAM_ID_PAIR,  /* +1 per extra picker row: picker row thresholds */
  NAM_ID_TAIL,  /* +(extra ids - extra rows): picker row -> id offset for the rows after the extra ones */
  NAM_ID_CAP    /* +4 bytes per extra id: capacity of id-indexed vectors / the prototype table */
};

typedef struct
{
  uint32_t vaddr, old_w;
  int kind;
} NamIdSite;

/* where an id-indexed table goes when it grows */
enum
{
  NAM_PLACE_IN_PLACE, /* extend where it is: the 8 bytes past its end are the (relocated) neighbor's first entries */
  NAM_PLACE_CAVE,     /* relocate into the R+E gap */
  NAM_PLACE_RW_TAIL   /* relocate into the zero slack at the end of the R+W segment's file-backed range */
};

typedef struct
{
  uint32_t base;
  const char* what;
  int place;
  uint32_t sites[2];  /* movw/movt readers to repoint (0-terminated), unused when in place */
  bool distinct_pair; /* entries 165/166 are different pointers ("X"/"X 2" editor paths), not equal */
} NamIdTable;

#define NAM_MAX_NAME_READERS 4

typedef struct
{
  const char* model;
  bool experimental; /* derived, never run on hardware */

  /* ---- registry ---- */
  uint32_t types_start_lit, types_end_lit; /* ctor literals: types array start (header word) / end (last entry) */
  uint32_t names_lit_ctor, names_lit_map;  /* literals holding name array base - 4 */
  uint32_t map_end_insn, map_end_insn_old; /* add rX, rY, #0x2a0 -> end of the name array */
  uint32_t cmp_last_idx, cmp_last_idx_old; /* ctor: cmp rX, #0xa7 */
  uint32_t cmp_count, cmp_count_old;       /* ctor: cmp rX, #0xa8 */
  uint32_t statemap_new_a, statemap_new_a_old; /* mov r0, #0xa40: StateMap-sized allocations */
  uint32_t statemap_new_b, statemap_new_b_old;
  uint32_t memset_sz, memset_sz_old;           /* ctor: mov r2, #0x298 (in-object prototype table) */
  uint32_t short_loop_cmp, short_loop_cmp_old; /* cmp rX, #0xa7 of a loop over the names */
  uint32_t types_start, types_end, names_base, short_base;
  uint32_t names_movw[NAM_MAX_NAME_READERS]; /* movw/movt readers of the name array base (0-terminated) */
  uint32_t names16_lits[NAM_MAX_NAME_READERS]; /* literal readers of names+16 (0-terminated) */
  uint32_t short_movw;

  /* ---- picker catalog hook ---- */
  uint32_t modfac_construct, modfac_jt; /* ModFac_construct and its 92-entry case table */
  uint32_t cat_call_site, cat_call_site_old;   /* bl vec_build of the Distortion list */
  uint32_t cat2_call_site, cat2_call_site_old; /* bl vec_build of the Reverb list */
  uint32_t cat_veneer;                         /* dead case-84 body */
  uint32_t cat2_veneer, cat2_veneer_old;       /* dead case-82 body */
  uint32_t cat_str_range_ctor, cat_str_cstr_ctor, cat_vec_build;

  const NamIdTable* tables;
  size_t ntables;
  const NamIdSite* id_sites;
  size_t n_id_sites;

  /* ---- property nodes ---- */
  uint32_t node_call_a, node_call_a_w; /* bl node_fn for "Glorious Drive 2" */
  uint32_t node_call_b, node_call_b_w; /* bl link_fn for "Glorious Drive" */
  uint32_t node_veneer_a, node_veneer_a_w, node_veneer_b, node_veneer_b_w; /* inside the dead case-84 body */
  uint32_t activate_all, activate_all_w0, activate_all_w1;                 /* its first two instructions move */
  uint32_t picker_exit, picker_exit_w0, picker_exit_w1; /* the picker's "both instances in use" exit (4-id pedals) */
  uint32_t picker_fn, picker_ok;                        /* hook D's helper call and success target */
  uint32_t node_fn, link_fn, gd_desc, activate_fn;      /* hooks A-C: node builder, path linker, GD descriptors */

  /* ---- engine class ---- */
  uint32_t eng_case_vtt_lit, eng_case_vtt_old, eng_case_vt_lit, eng_case_vt_old; /* dead case 80's literals */
  uint32_t eng_gd_vtt_lit, eng_gd_vt_lit;                                        /* Glorious Drive's (case 91) */
  uint32_t eng_mod_vt, eng_setup_fn, eng_vt, eng_vt_lit, eng_process_fn;

  /* ---- debug spies (0 = not available for this model) ---- */
  uint32_t modfac_vtable;
} SpyTarget;

/* The target for a model name ("pedalboard" | "mx5" | "gigboard"), NULL if the additive pedals have no target there. */
const SpyTarget* nam_spy_target(const char* model);

/* Debug: ModFac_construct spy. Repoints slot 7 of the ModFac vtable at a trampoline that appends a 64-byte record
 * {r0, r1 (pedal type index), lr, sp, 12 stack words} to /tmp/modfac.bin, then tail-jumps to the real
 * ModFac_construct. Patches `data` IN PLACE; refuses on any mismatch. Returns the trampoline vaddr via out_tramp. */
bool nam_elf_patch_modfac_spy(const SpyTarget* t, uint8_t* data, size_t data_len, uint32_t* out_tramp, char* err,
                              size_t err_size);

#define NAM_MAX_PAIRS 3

/* Picker category a pair's names are listed under. */
#define NAM_CAT_DISTORTION 0u
#define NAM_CAT_REVERB 1u

typedef struct
{
  const char* name;       /* "<name>" and "<name> 2" become pedals; at most 12 characters */
  const char* short_name; /* short names, likewise */
  uint32_t type_idx;      /* existing ModFac type the pair is built as (91 = Glorious Drive) */
  uint32_t instances;     /* ids owned: 2 (default, "<n>", "<n> 2") or 4 ("<n>" .. "<n> 4", then it must be the only pedal) */
  uint32_t category;      /* NAM_CAT_DISTORTION (0, default) or NAM_CAT_REVERB: the picker list the name appears in */
} NamPair;

/* Registers `npairs` extra "<name>" / "<name> 2" pedal pairs after the last normal pair (ids 167..166+2n; FX-Loop,
 * Input, Output and Mix move up by 2n) by relocating the boot-time pedal registry (type-index array, name and
 * short-name arrays, descriptor tables) and bumping every hard-coded id constant. Refuses on any mismatch. Does not
 * make the pedals usable on its own: call nam_elf_patch_node_registration afterwards. */
bool nam_elf_patch_registry(const SpyTarget* t, uint8_t* data, size_t data_len, const NamPair* pairs, uint32_t npairs,
                            char* err, size_t err_size);

/* One-pair convenience wrapper. */
bool nam_elf_patch_registry_test(const SpyTarget* t, uint8_t* data, size_t data_len, const char* name,
                                 const char* short_name, uint32_t type_idx, char* err, size_t err_size);

/* Registers the StateMap property nodes, links and value sources for the pairs added by nam_elf_patch_registry
 * (call it after that, with the same pairs). Without it the pedals crash on save, or show transparent with dead
 * knobs. */
bool nam_elf_patch_node_registration(const SpyTarget* t, uint8_t* data, size_t data_len, const NamPair* pairs,
                                     uint32_t npairs, uint32_t* out_init_slot, uint32_t* out_eng_tab, char* err,
                                     size_t err_size);
/* *out_init_slot: writable word hook C calls through once the nodes are active, as fn(triples, count, builder) (0 =
 * skipped); libnam_preload.so fills it. *out_eng_tab: {count, 8 x {engine, &name QString}} the engine stub fills
 * (pass it to nam_elf_patch_engine_class). Both may be NULL. */

/* ModFac type the extra pedals must be built as to get their own audio engine (pass it as NamPair.type_idx). */
#define NAM_ENGINE_TYPE 80u

/* Gives type NAM_ENGINE_TYPE its own module+engine vtables (clones of Glorious Drive's) whose engine process() jumps
 * through a writable hook slot, returned in *out_hook_slot (libnam_preload.so fills it; it is 0 = original
 * process() until then). ids = number of extra ids the registry patch added. Call after nam_elf_patch_registry. */
bool nam_elf_patch_engine_class(const SpyTarget* t, uint8_t* data, size_t data_len, uint32_t ids, uint32_t eng_tab,
                                bool record_hook, uint32_t* out_hook_slot, char* err, size_t err_size);
/* record_hook: instead of filling the {engine, &name} table the stub calls record(engine, &name QString) through the
 * word at eng_tab right when the pedal is created (0 = no call until libnam_preload.so fills it). The table design
 * cannot tell pedals apart by name: the name is a temporary of the caller and is gone by the time audio runs. */

/* Debug: logs every call through the qt_static_metacall-style dispatcher at 0x86798 (method index, arguments) to
 * /tmp/meta.bin, to see what the block-type picker asks the UI model. Pedalboard 2.7 only.
 * `method_mask` bit i selects dispatcher method index i (all 49: 0x1ffffffffffff). */
bool nam_elf_patch_metacall_spy(const SpyTarget* t, uint8_t* data, size_t data_len, uint64_t method_mask, char* err,
                                size_t err_size);

#endif
