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


### Étape 3 : Analyse du comportement

On va maintenant chercher à comprendre [élément à analyser].

```bash
[Commande ou manipulation effectuée]
```

```bash
[Résultat obtenu]
```

[Explication technique : organisation mémoire, comportement du programme, valeurs obtenues, etc.]

### Étape 4 : Exploitation

Maintenant que nous avons identifié [élément nécessaire], nous allons essayer de [objectif de l'étape].

```bash
[Commande ou script utilisé]
```

[Explication du fonctionnement de la commande et des éléments importants.]

```bash
[Résultat obtenu]
```

[Interprétation du résultat et vérification de la réussite.]

### Étape 5 : Vérification de l'accès / Résultat final

[Dernière manipulation permettant de vérifier que l'exploitation a fonctionné.]

```bash
[Commande utilisée]
```

```bash
[Résultat obtenu]
```

On vérifie [élément permettant de confirmer la réussite].

[Conclusion : validation du challenge et résultat obtenu.]

---

## 4. Comment se protéger ?

Ici, l'erreur venait de [origine de la vulnérabilité].

[Explication de la mauvaise pratique ou de l'erreur de programmation.]

Pour corriger ce problème, plusieurs solutions sont possibles :

- [Première mesure corrective]
- [Deuxième mesure corrective]
- [Troisième mesure corrective]

[Conclusion sur les bonnes pratiques permettant d'éviter cette vulnérabilité.]
