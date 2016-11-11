#include <stdio.h>
#include <string.h>
#include "assinaLib.h"

int main(int argc, char** argv ){

    char* pin="123456";
    char* token="qualiconsult                    QualiConsult                    MCard Applet    ";
    char* cka="chave de teste";
    char* byte="funfa";
    char *byte64="ZnVuZmE=";
    char* byte2="dasdasdasdhasduqawodqwheqiweoqwujepiu0273019287-9128v412094812ejlwdjlaskdjhlkashdlakshdalsk";


    char* saida2 = malloc(345);


    assina(token,pin,cka,byte,0,saida2,345);
    printf("Saida:%s\n",saida2);
    free(saida2);


}