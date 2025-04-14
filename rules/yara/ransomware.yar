/*
   Règles YARA pour la détection de ransomwares
   Créé par: BioCybe
   Date: Avril 2025
*/

import "hash"
import "pe"
import "math"

// Détection générique de comportements de ransomware
rule Generic_Ransomware_Behavior {
    meta:
        description = "Détecte des comportements génériques de ransomware"
        author = "BioCybe"
        date = "2025-04-14"
        version = "1.0"
        severity = "high"
        category = "ransomware"
        
    strings:
        // Chaînes liées au chiffrement
        $encrypt1 = "AES" nocase
        $encrypt2 = "RSA" nocase
        $encrypt3 = "encrypt" nocase
        $encrypt4 = "crypt" nocase
        $encrypt5 = "lock" nocase
        
        // Extensions courantes de ransomware
        $ext1 = ".locked" nocase
        $ext2 = ".crypt" nocase
        $ext3 = ".encrypted" nocase
        $ext4 = ".pay" nocase
        $ext5 = ".ransom" nocase
        
        // Messages de rançon
        $msg1 = "bitcoin" nocase
        $msg2 = "BTC" nocase
        $msg3 = "monero" nocase
        $msg4 = "XMR" nocase
        $msg5 = "recover" nocase
        $msg6 = "files" nocase
        $msg7 = "pay" nocase
        $msg8 = "decrypt" nocase
        
        // Tentatives de suppression des sauvegardes
        $del1 = "vssadmin delete shadows" nocase
        $del2 = "wmic shadowcopy delete" nocase
        $del3 = "bcdedit /set" nocase
        $del4 = "wbadmin delete" nocase
        
    condition:
        (uint16(0) == 0x5A4D) and // Fichier PE
        (
            (2 of ($encrypt*)) or
            (2 of ($ext*)) or
            (4 of ($msg*)) or
            (1 of ($del*))
        ) and
        filesize < 10MB
}

// Exemple de détection spécifique pour une famille
rule Ransomware_Family_Cerber {
    meta:
        description = "Détecte la famille de ransomware Cerber"
        author = "BioCybe"
        date = "2025-04-14"
        version = "1.0"
        severity = "critical"
        category = "ransomware"
    
    strings:
        $cerber_str1 = { 55 8B EC 83 EC 44 53 56 57 8B 75 08 8B }
        $cerber_str2 = { 68 ?? ?? ?? ?? FF 55 ?? 83 C4 ?? 85 C0 74 }
        $cerber_marker = "Cerber" nocase
        $cerber_ext = ".cerber" nocase
        $ransom_note = { 23 20 44 45 43 52 59 50 54 20 49 4E 53 54 52 55 43 54 49 4F 4E 20 23 }
        
    condition:
        (uint16(0) == 0x5A4D) and
        (
            ($cerber_marker and $cerber_ext) or
            ($ransom_note) or
            all of ($cerber_str*)
        )
}

// Détection basée sur des comportements avancés
rule Advanced_Ransomware_Behavior {
    meta:
        description = "Détecte des comportements avancés de ransomware utilisant des techniques d'évasion"
        author = "BioCybe"
        date = "2025-04-14"
        version = "1.0"
        severity = "critical"
        category = "ransomware"
        
    strings:
        // API de chiffrement
        $api1 = "CryptEncrypt" nocase
        $api2 = "CryptGenRandom" nocase
        $api3 = "CryptCreateHash" nocase
        $api4 = "CryptAcquireContext" nocase
        
        // Techniques d'évasion
        $evasion1 = "IsDebuggerPresent" nocase
        $evasion2 = "CheckRemoteDebuggerPresent" nocase
        $evasion3 = "GetTickCount" nocase
        $evasion4 = "QueryPerformanceCounter" nocase
        $evasion5 = "Sleep" nocase
        
        // Énumération de fichiers
        $enum1 = "FindFirstFile" nocase
        $enum2 = "FindNextFile" nocase
        $enum3 = "GetLogicalDrives" nocase
        
    condition:
        (uint16(0) == 0x5A4D) and
        (
            (3 of ($api*)) and
            (2 of ($evasion*)) and
            (2 of ($enum*))
        ) and
        pe.sections[0].entropy > 6.8 and
        pe.sections[1].entropy > 6.5
}

// Danger Theory - Signaux comportementaux
rule Danger_Theory_Ransomware_Signals {
    meta:
        description = "Détecte des signaux de danger liés aux ransomwares selon la Danger Theory"
        author = "BioCybe"
        date = "2025-04-14"
        version = "1.0"
        severity = "high"
        category = "danger_theory"
        
    strings:
        // Accès multiples aux fichiers
        $file_op1 = "WriteFile" nocase
        $file_op2 = "CreateFile" nocase
        $file_op3 = "SetFileAttributes" nocase
        $file_op4 = "MoveFile" nocase
        $file_op5 = "DeleteFile" nocase
        
        // Opérations réseau suspicieuses
        $net_op1 = "connect" nocase
        $net_op2 = "InternetOpen" nocase
        $net_op3 = "send" nocase
        $net_op4 = "recv" nocase
        
        // Manipulation de processus
        $proc_op1 = "CreateProcess" nocase
        $proc_op2 = "TerminateProcess" nocase
        $proc_op3 = "OpenProcess" nocase
        
        // Lecture d'informations système
        $sys_op1 = "GetSystemDirectory" nocase
        $sys_op2 = "GetSystemInfo" nocase
        $sys_op3 = "GetUserName" nocase
        $sys_op4 = "GetComputerName" nocase
        
    condition:
        (uint16(0) == 0x5A4D) and
        (
            (4 of ($file_op*)) and
            (2 of ($net_op*) or 2 of ($proc_op*)) and
            (2 of ($sys_op*))
        ) and
        filesize < 5MB
}

// Détection de comportements de polymorphisme
rule Polymorphic_Ransomware {
    meta:
        description = "Détecte des techniques de polymorphisme utilisées par des ransomwares"
        author = "BioCybe"
        date = "2025-04-14"
        version = "1.0"
        severity = "critical"
        category = "ransomware"
        
    strings:
        // Instructions d'auto-modification
        $self_mod1 = { C7 ?? ?? ?? ?? ?? ?? ?? ?? E9 }
        $self_mod2 = { 81 ?? ?? ?? ?? ?? ?? ?? ?? 89 }
        
        // Déchiffrement en mémoire
        $decrypt1 = { 8A ?? ?? 34 ?? 88 ?? ?? 40 3B ?? 72 ?? }
        $decrypt2 = { 8B ?? ?? 81 ?? ?? ?? ?? ?? 89 ?? ?? 83 ?? ?? 72 ?? }
        $decrypt3 = { 8A ?? ?? 2A ?? ?? 88 ?? ?? 46 3B ?? 72 ?? }
        
        // Séquences de saut dynamiques
        $jmp1 = { FF 25 ?? ?? ?? ?? }
        $jmp2 = { E9 ?? ?? ?? ?? }
        
    condition:
        (uint16(0) == 0x5A4D) and
        (
            (1 of ($self_mod*)) or
            (2 of ($decrypt*)) or
            (all of ($jmp*))
        ) and
        pe.sections[0].entropy > 7.2
}

// Détection basée sur l'immunité collective (partage de connaissances)
rule Collective_Immunity_Ransomware {
    meta:
        description = "Détecte des ransomwares basés sur des connaissances partagées (immunité collective)"
        author = "BioCybe"
        date = "2025-04-14"
        version = "1.0"
        severity = "high"
        category = "ransomware"
        threat_id = "BIOCYBE-RTI-2025-0134"
        
    strings:
        // Signatures partagées par la communauté
        $shared1 = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 }
        $shared2 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 }
        $shared3 = { 56 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 }
        
        // Comportements observés collectivement
        $community1 = "attack_vector_1" xor
        $community2 = "attack_pattern_2" base64
        $community3 = { 55 8B EC 83 EC 40 53 56 57 8D 45 ?? 50 }
        
    condition:
        (uint16(0) == 0x5A4D) and
        (
            (2 of ($shared*)) or
            (2 of ($community*))
        ) and
        filesize < 8MB
}
