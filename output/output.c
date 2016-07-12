#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main() {
    FILE *fp;
    uint8_t *ch = "hahhaha";
    int size = sizeof(ch);
    char char_str[5];
    if((fp=fopen("myfile.txt","a+"))==NULL) {  
        printf("file cannot be opened/n");   
        exit(1);  
    }
    int i;
    for (i=0;i<size;i++)
    {
        sprintf(char_str,"%u", ch[i]);
        fputs(char_str,fp);
        fputs(" ",fp);
    }
    fputs("\n",fp);
    fclose(fp); 
}   
