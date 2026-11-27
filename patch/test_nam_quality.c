/* test_nam_quality.c -- exercises the per-pedal NAM quality modes of libnam_hook.so (namespace quality in nam_hook.cpp)
 * through nam_process_eng() and two fake engine objects, the way test_nam_eng.c does. Each engine is recorded with a
 * pedal name through nam_eng_record (as the engine stub does when a pedal is created; the caller's QString is wiped
 * right after, as on the device): A = "NAM", B = "NAM 2". Then it "clicks" buttons by opening
 * /tmp/nam_mode/<pedal>-<mode>.png the way the page's Image does, and checks the saved file and the state file; the
 * reload each click causes shows in the hook's [nam_load] lines (printed with the engine address).
 *   NAM_MODEL_DIR=/m ./test_nam_quality   (libnam_hook.so at /t, a slimmable model in /m)
 * With NAM_AUTO_MARGIN set (e.g. 20: emulation is several times slower, so AUTO would never pick Full) it also feeds
 * B a stereo input, which must drop its AUTO Full ("(full blocked)"), then picks AUTO again on a mono input (Full
 * again). Add NAM_AUTO_OVERRUN_US=1000000 so only the stereo check can fire. Phases run thousands of blocks (minutes
 * in qemu). */
#include <dlfcn.h>
#include <fcntl.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef void (*proc_fn)(void*, uint32_t, float**, uint32_t, float**, int32_t, uint32_t*, void*);
typedef void (*start_fn)(void);
typedef void (*record_fn)(void*, const void*);

/* a Qt 5 QString as the hook reads it: QString = pointer to QArrayData{ref, size, alloc, offset}, UTF-16 at +offset */
static struct
{
  uint32_t ref, size, alloc, offset;
  uint16_t text[16];
} g_qdata;
static uint32_t g_qstring;

static proc_fn fn;
static uint8_t eng_a[0x700], eng_b[0x700];

static void record(record_fn rec, void* eng, const char* name)
{
  memset(&g_qdata, 0, sizeof(g_qdata));
  g_qdata.size = (uint32_t)strlen(name);
  g_qdata.offset = (uint32_t)((uintptr_t)g_qdata.text - (uintptr_t)&g_qdata);
  for (size_t i = 0; i < strlen(name); i++)
    g_qdata.text[i] = (uint16_t)name[i];
  g_qstring = (uint32_t)(uintptr_t)&g_qdata;
  rec(eng, &g_qstring);
  memset(&g_qdata, 0, sizeof(g_qdata)); /* a temporary of the caller: gone by the time audio runs */
  g_qstring = 0;
}

static void init_engine(uint8_t* eng)
{
  memset(eng, 0, 0x700);
  *(float*)(eng + 0x554) = 0.0f; /* model 1 */
  *(float*)(eng + 0x540) = 0.5f;
  *(float*)(eng + 0x568) = 0.5f;
}

/* both engines, one block each per iteration; b_stereo: B gets different signals on its two channels */
static void run_blocks(int n, int b_stereo)
{
  enum { N = 48 };
  static float in0[N], in1[N], out0[N], out1[N];
  static int phase;
  float* ip[2] = {in0, in1};
  float* op[2] = {out0, out1};
  uint32_t flags = 0;
  for (int b = 0; b < n; b++)
  {
    for (int i = 0; i < N; i++, phase++)
      in0[i] = in1[i] = 0.3f * sinf(2.0f * (float)M_PI * 220.0f * phase / 48000.0f);
    fn(eng_a, 0, ip, 2, op, N, &flags, NULL);
    if (b_stereo)
      for (int i = 0; i < N; i++)
        in1[i] = 0.3f * sinf(2.0f * (float)M_PI * 330.0f * (phase - N + i) / 48000.0f);
    fn(eng_b, 0, ip, 2, op, N, &flags, NULL);
    usleep(2000);
  }
}

static int file_has(const char* path, const char* text)
{
  char buf[512] = {0};
  FILE* f = fopen(path, "r");
  if (!f)
    return 0;
  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  fclose(f);
  buf[n] = 0;
  return strstr(buf, text) != NULL;
}

static void click(const char* file)
{
  char path[96];
  snprintf(path, sizeof(path), "/tmp/nam_mode/%s.png", file);
  int fd = open(path, O_RDONLY);
  if (fd >= 0)
    close(fd);
  printf("--- clicked %s (open %s)\n", file, fd >= 0 ? "ok" : "FAILED");
  fflush(stdout);
  usleep(300000);
}

static int check(int ok, const char* what)
{
  printf("%s %s\n", ok ? "ok  " : "FAIL", what);
  fflush(stdout);
  return ok ? 0 : 1;
}

int main(void)
{
  void* lib = dlopen("/t/libnam_hook.so", RTLD_NOW);
  if (!lib)
  {
    printf("dlopen failed: %s\n", dlerror());
    return 2;
  }
  fn = (proc_fn)dlsym(lib, "nam_process_eng");
  start_fn start = (start_fn)dlsym(lib, "nam_quality_start");
  record_fn rec = (record_fn)dlsym(lib, "nam_eng_record");
  if (!fn || !start || !rec)
  {
    printf("missing symbols\n");
    return 3;
  }
  const char* dir = getenv("NAM_MODEL_DIR");
  char conf[256];
  snprintf(conf, sizeof(conf), "%s/nam_quality.txt", dir ? dir : ".");
  unlink(conf);

  init_engine(eng_a);
  init_engine(eng_b);
  printf("engine A (\"NAM\") = %p, engine B (\"NAM 2\") = %p\n", (void*)eng_a, (void*)eng_b);
  record(rec, eng_a, "NAM");
  record(rec, eng_b, "NAM 2");
  start();
  usleep(800000);

  int rc = 0;
  rc |= check(access("/tmp/nam_mode/NAM-full.png", F_OK) == 0 && access("/tmp/nam_mode/NAM_2-lite.png", F_OK) == 0,
              "trigger images for both pedals");
  rc |= check(file_has("/tmp/nam_mode_state.qml", "\"NAM\": 0") && file_has("/tmp/nam_mode_state.qml", "\"NAM 2\": 0"),
              "state: both AUTO at start");
  run_blocks(3000, 0);

  click("NAM_2-full");
  run_blocks(3000, 0);
  rc |= check(file_has(conf, "NAM 2=full") && file_has(conf, "NAM=auto"), "saved: NAM 2 full, NAM auto");
  rc |= check(file_has("/tmp/nam_mode_state.qml", "\"NAM 2\": 2") && file_has("/tmp/nam_mode_state.qml", "\"NAM\": 0"),
              "state: NAM 2 FULL, NAM AUTO");

  click("NAM-lite");
  run_blocks(3000, 0);
  rc |= check(file_has(conf, "NAM 2=full") && file_has(conf, "NAM=lite"), "saved: NAM 2 full, NAM lite");

  if (getenv("NAM_AUTO_MARGIN"))
  {
    click("NAM_2-auto");
    run_blocks(4000, 0);
    printf("--- stereo input into B\n");
    fflush(stdout);
    run_blocks(4000, 1);
    click("NAM_2-auto");
    printf("--- mono input again\n");
    fflush(stdout);
    run_blocks(4000, 0);
  }
  printf("done rc=%d (A = %p, B = %p: check the [nam_load] lines above)\n", rc, (void*)eng_a, (void*)eng_b);
  return rc;
}
