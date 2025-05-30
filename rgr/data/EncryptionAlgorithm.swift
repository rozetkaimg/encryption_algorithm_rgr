//
//  EncryptionAlgorithm.swift
//  rgr
//
//  Created by Stanislav Klepikov on 19.05.2025.
//
enum EncryptionAlgorithm: String, CaseIterable, Identifiable {
    case staticEncrypt = "Шифровка зафиксированной перестановкой"
    case rsa = "RSA"
    case gost  = "ГОСТ 28147-89"
    var id: String { self.rawValue }
}


