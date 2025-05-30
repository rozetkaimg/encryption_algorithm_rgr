//
//  EncryptionAlgorithm.swift
//  rgr
//
//  Created by Stanislav Klepikov on 19.05.2025.
//
enum EncryptionAlgorithm: String, CaseIterable, Identifiable {
    case rsa = "RSA"
    case gost = "ГОСТ 28147-89"
    case fixedPermutation = "Фиксированная перестановка"
    case staticEncrypt = "Static Shift (демо)"
    var id: String { self.rawValue }
}
