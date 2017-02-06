/* ARM-specific configuration */
#include "android/config/config.h"

#define TARGET_ARM 1
#define CONFIG_SOFTFLOAT 1

#if defined(CONFIG_LINUX) && defined(HOST_X86_64)
#define CONFIG_SPT  1
#endif


