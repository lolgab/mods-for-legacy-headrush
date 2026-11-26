/* test_nam_quality.c -- exercises the NAM quality modes of libnam_hook.so (namespace quality in nam_hook.cpp) through
 * nam_process_eng() and a fake engine object, the way test_nam_eng.c does: starts the mode watcher, loads a slimmable
 * model from NAM_MODEL_DIR in AUTO, then "clicks" FULL, LITE and AUTO by opening /tmp/nam_mode/<mode>.png the way the
 * page's Image does, and checks that each one reloads the model at the expected size (read back from the hook's
 * journal lines, which this test prints), that the choice is saved to <model dir>/nam_quality.txt, and that
 * /tmp/nam_mode_state.qml follows. Run on ARM (or under qemu) with the model dir and the library mounted:
 *   NAM_MODEL_DIR=/m ./test_nam_quality   (libnam_hook.so at /t)
 * With NAM_AUTO_MARGIN set (e.g. 20: emulation is several times slower, so AUTO would never pick Full) it also feeds
 * a stereo input, which must drop AUTO's Full ("(full blocked)"), then picks AUTO again on a mono input (Full again).
 * Add NAM_AUTO_OVERRUN_US=1000000 so only the stereo check can fire. Each phase runs 5000 blocks (minutes in qemu). */
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

static proc_fn fn;
static uint8_t eng[0x700];

/* stereo = 0: the same signal on both channels (dual mono, one model run); 1: different signals (two runs) */
static void run_blocks(int n, int stereo)
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
    {
      in0[i] = 0.3f * sinf(2.0f * (float)M_PI * 220.0f * phase / 48000.0f);
      in1[i] = stereo ? 0.3f * sinf(2.0f * (float)M_PI * 330.0f * phase / 48000.0f) : in0[i];
    }
    fn(eng, 0, ip, 2, op, N, &flags, NULL);
    usleep(2000);
  }
}

static int file_has(const char* path, const char* text)
{
  char buf[256] = {0};
  FILE* f = fopen(path, "r");
  if (!f)
    return 0;
  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  fclose(f);
  buf[n] = 0;
  return strstr(buf, text) != NULL;
}

static void click(const char* mode)
{
  char path[64];
  snprintf(path, sizeof(path), "/tmp/nam_mode/%s.png", mode);
  int fd = open(path, O_RDONLY);
  if (fd >= 0)
    close(fd);
  printf("--- clicked %s (open %s)\n", mode, fd >= 0 ? "ok" : "FAILED");
  fflush(stdout);
  usleep(200000);
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
  if (!fn || !start)
  {
    printf("missing symbols\n");
    return 3;
  }
  const char* dir = getenv("NAM_MODEL_DIR");
  char conf[256];
  snprintf(conf, sizeof(conf), "%s/nam_quality.txt", dir ? dir : ".");
  unlink(conf);

  start();
  usleep(300000);
  int rc = 0;
  if (!file_has("/tmp/nam_mode_state.qml", "mode: 0"))
  {
    printf("FAIL state file not AUTO at start\n");
    rc = 1;
  }

  memset(eng, 0, sizeof(eng));
  *(float*)(eng + 0x554) = 0.0f; /* model 1 */
  *(float*)(eng + 0x540) = 0.5f;
  *(float*)(eng + 0x568) = 0.5f;
  run_blocks(5000, 0);

  const char* modes[] = {"full", "lite", "auto"};
  const char* states[] = {"mode: 2", "mode: 1", "mode: 0"};
  for (int i = 0; i < 3; i++)
  {
    click(modes[i]);
    run_blocks(5000, 0);
    if (!file_has(conf, modes[i]))
    {
      printf("FAIL %s not saved to %s\n", modes[i], conf);
      rc = 1;
    }
    if (!file_has("/tmp/nam_mode_state.qml", states[i]))
    {
      printf("FAIL state file not %s\n", states[i]);
      rc = 1;
    }
  }
  /* AUTO's watchdog: with NAM_AUTO_MARGIN large enough for Full, a stereo input must drop it to the smaller size
   * ("(full blocked)"), and picking AUTO again must retry Full */
  if (getenv("NAM_AUTO_MARGIN"))
  {
    printf("--- stereo input\n");
    fflush(stdout);
    run_blocks(5000, 1);
    click("auto");
    printf("--- mono input again\n");
    fflush(stdout);
    run_blocks(5000, 0);
  }
  printf("done rc=%d (check the [nam_load] lines above)\n", rc);
  return rc;
}
