#include "osapi.h"
#include "user_interface.h"
uint32 ICACHE_FLASH_ATTR user_rf_cal_sector_set(void)
{
    switch (system_get_flash_size_map()) {
        case FLASH_SIZE_4M_MAP_256_256:
            return 128 - 5;
        case FLASH_SIZE_8M_MAP_512_512:
            return 256 - 5;

        case FLASH_SIZE_16M_MAP_512_512:
        case FLASH_SIZE_16M_MAP_1024_1024:
            return 512 - 5;

        case FLASH_SIZE_32M_MAP_512_512:
        case FLASH_SIZE_32M_MAP_1024_1024:
            return 1024 - 5;

        case FLASH_SIZE_64M_MAP_1024_1024:
            return 2048 - 5;

        case FLASH_SIZE_128M_MAP_1024_1024:
            return 4096 - 5;
        default:
            return 0;
    }

}
void ICACHE_FLASH_ATTR user_init(void) {}