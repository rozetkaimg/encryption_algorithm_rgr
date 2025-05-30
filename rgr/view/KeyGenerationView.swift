//
//  Generator.swift
//  rgr
//
//  Created by Stanislav Klepikov on 30.05.2025.
//

import SwiftUI

struct KeyGenerationView: View {
    @State private var selectedAlgorithm: EncryptionAlgorithm = .rsa
    
    // RSA Keys
    @State private var rsaNKey: String = ""
    @State private var rsaEKey: String = ""
    @State private var rsaDKey: String = ""
    @State private var rsaKeyBits: Int = 512 // Default RSA key size
    let rsaBitSizes = [256, 512, 1024, 2048] // Example bit sizes

    // GOST Keys
    @State private var gostKeyHex: String = ""
    @State private var gostIvHex: String = ""

    // Permutation Key
    @State private var permutationKeyLength: Int = 5 // Default length for permutation key
    @State private var generatedPermutationKey: String = ""
    let permutationKeyLengths = [3, 4, 5, 6, 7, 8, 9, 10]


    @State private var feedbackMessage: String = "Выберите алгоритм для генерации ключей."
    @State private var isProcessing: Bool = false

    private let rsaWrapper = RSAObjectiveCWrapper()
    private let gostWrapper = GOSTObjectiveCWrapper()

    var body: some View {
        VStack(spacing: 20) {
            Text("Генератор Ключей")
                .font(.largeTitle)
                .padding(.bottom, 10)

            Picker("Алгоритм:", selection: $selectedAlgorithm) {
                ForEach(EncryptionAlgorithm.allCases.filter { $0.isKeyGeneratable }) { algorithm in
                    Text(algorithm.rawValue).tag(algorithm)
                }
            }
            .onChange(of: selectedAlgorithm) { _ in
                resetKeyFields()
                updateFeedbackForAlgorithmChange()
            }
            .padding(.horizontal)

            // --- Specific controls for each algorithm ---
            if selectedAlgorithm == .rsa {
                rsaKeyGenerationControls
            } else if selectedAlgorithm == .gost {
                gostKeyGenerationControls
            } else if selectedAlgorithm == .fixedPermutation {
                permutationKeyGenerationControls
            }

            Button(action: generateKeys) {
                HStack {
                    Image(systemName: "key.fill")
                    Text("Сгенерировать Ключи")
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(isProcessing || !selectedAlgorithm.isKeyGeneratable) // Disable if not generatable
            .padding(.top)


            if isProcessing {
                ProgressView().padding()
            }
            
            keyDisplayArea()
            
            if !feedbackMessage.isEmpty {
                Text(feedbackMessage)
                    .font(.caption)
                    .foregroundColor(determineFeedbackColor())
                    .padding(.top, 5)
                    .multilineTextAlignment(.center)
            }
            
            Spacer()
        }
        .padding()
        .frame(minWidth: 500, idealWidth: 600, minHeight: 550, idealHeight: 700)
        .onAppear(perform: updateFeedbackForAlgorithmChange)
    }

    // MARK: - Algorithm Specific Controls
    
    private var rsaKeyGenerationControls: some View {
        VStack {
            Text("Размер ключа RSA (бит):")
            Picker("Размер ключа:", selection: $rsaKeyBits) {
                ForEach(rsaBitSizes, id: \.self) { bits in
                    Text("\(bits)").tag(bits)
                }
            }
            .pickerStyle(SegmentedPickerStyle())
            .padding(.bottom)
            Text("Примечание: Генерация RSA ключей может занять некоторое время, особенно для больших размеров.")
                .font(.caption2)
                .foregroundColor(.gray)
        }
        .padding(.vertical)
    }
    
    private var gostKeyGenerationControls: some View {
        VStack {
            // No specific controls needed for GOST key/IV generation beyond the button itself
            Text("Будут сгенерированы 256-битный ключ и 64-битный IV для ГОСТ.")
                .font(.subheadline)
                .padding()
        }
    }
    
    private var permutationKeyGenerationControls: some View {
        VStack {
            Text("Длина ключа перестановки (размер блока):")
            Picker("Длина ключа:", selection: $permutationKeyLength) {
                ForEach(permutationKeyLengths, id: \.self) { length in
                    Text("\(length)").tag(length)
                }
            }
             .pickerStyle(SegmentedPickerStyle())
            Text("Будет сгенерирована случайная перестановка цифр 0..N-1.")
                .font(.caption2)
                .foregroundColor(.gray)
        }
        .padding(.vertical)
    }

    // MARK: - Key Display Area
    @ViewBuilder
    private func keyDisplayArea() -> some View {
        if !isProcessing {
            VStack(alignment: .leading, spacing: 10) {
                if selectedAlgorithm == .rsa && (!rsaNKey.isEmpty || !rsaEKey.isEmpty || !rsaDKey.isEmpty) {
                    keyField(label: "RSA N (hex):", value: rsaNKey)
                    keyField(label: "RSA E (hex, public):", value: rsaEKey)
                    keyField(label: "RSA D (hex, private):", value: rsaDKey)
                } else if selectedAlgorithm == .gost && (!gostKeyHex.isEmpty || !gostIvHex.isEmpty) {
                    keyField(label: "ГОСТ Ключ (hex):", value: gostKeyHex)
                    keyField(label: "ГОСТ IV (hex):", value: gostIvHex)
                } else if selectedAlgorithm == .fixedPermutation && !generatedPermutationKey.isEmpty {
                    keyField(label: "Ключ перестановки:", value: generatedPermutationKey)
                }
            }
            .padding()
            .background(Color.secondary.opacity(0.1))
            .cornerRadius(8)
        }
    }

    @ViewBuilder
    private func keyField(label: String, value: String) -> some View {
        if !value.isEmpty {
            VStack(alignment: .leading) {
                Text(label).font(.headline)
                HStack {
                    Text(value)
                        .font(.system(.body, design: .monospaced))
                        .lineLimit(3)
                        .truncationMode(.tail)
                    Spacer()
                    Button { copyToClipboard(text: value, label: label.components(separatedBy: " ").first ?? "Ключ") } label: {
                        Image(systemName: "doc.on.doc")
                    }
                    .buttonStyle(.borderless)
                }
            }
        }
    }
    
    // MARK: - Helper Functions
    
    private func resetKeyFields() {
        rsaNKey = ""
        rsaEKey = ""
        rsaDKey = ""
        gostKeyHex = ""
        gostIvHex = ""
        generatedPermutationKey = ""
        // feedbackMessage might be set by updateFeedbackForAlgorithmChange
    }

    private func generateKeys() {
        guard !isProcessing else { return }
        isProcessing = true
        resetKeyFields()
        feedbackMessage = "Генерация ключей для \(selectedAlgorithm.rawValue)..."

        DispatchQueue.global(qos: .userInitiated).async {
            var tempFeedback = ""
            var success = false

            switch selectedAlgorithm {
            case .rsa:
                let keysString = rsaWrapper.generateRSAKeys(withBits: UInt32(rsaKeyBits))
                if keysString.starts(with: "Error:") {
                    tempFeedback = keysString
                } else {
                    let components = keysString.components(separatedBy: ";")
                    if components.count == 3 {
                        DispatchQueue.main.async {
                            self.rsaNKey = components[0]
                            self.rsaEKey = components[1]
                            self.rsaDKey = components[2]
                        }
                        tempFeedback = "RSA ключи (\(rsaKeyBits)-бит) успешно сгенерированы."
                        success = true
                    } else {
                        tempFeedback = "Ошибка: Неверный формат сгенерированных RSA ключей."
                    }
                }
            case .gost:
                let gKey = gostWrapper.generateGOSTKeyHex()
                let gIv = gostWrapper.generateGOSTIvHex()
                
                if gKey.starts(with: "Error:") || gIv.starts(with: "Error:") {
                    tempFeedback = "Ошибка генерации ГОСТ компонентов."
                    if gKey.starts(with: "Error:") { tempFeedback += " Ключ: \(gKey)." }
                    if gIv.starts(with: "Error:") { tempFeedback += " IV: \(gIv)." }
                } else {
                    DispatchQueue.main.async {
                        self.gostKeyHex = gKey
                        self.gostIvHex = gIv
                    }
                    tempFeedback = "ГОСТ ключ (256-бит) и IV (64-бит) успешно сгенерированы."
                    success = true
                }
            case .fixedPermutation:
                var p = Array(0..<permutationKeyLength)
                p.shuffle()
                let pKey = p.map { String($0) }.joined()
                DispatchQueue.main.async {
                    self.generatedPermutationKey = pKey
                }
                tempFeedback = "Ключ фиксированной перестановки (длина \(permutationKeyLength)) успешно сгенерирован."
                success = true
                
            case .staticEncrypt:
                tempFeedback = "Для Статического сдвига ключи не генерируются."
                // success remains false or handle appropriately
            }

            DispatchQueue.main.async {
                self.isProcessing = false
                self.feedbackMessage = tempFeedback
            }
        }
    }
    
    private func copyToClipboard(text: String, label: String) {
        #if os(macOS)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        feedbackMessage = "\(label) скопирован в буфер обмена."
        #elseif os(iOS)
        UIPasteboard.general.string = text
        feedbackMessage = "\(label) скопирован в буфер обмена."
        #endif
    }

    private func updateFeedbackForAlgorithmChange() {
        feedbackMessage = "Готово к генерации ключей для «\(selectedAlgorithm.rawValue)»."
        if !selectedAlgorithm.isKeyGeneratable {
            feedbackMessage = "Для «\(selectedAlgorithm.rawValue)» ключи не генерируются этим модулем."
        }
    }

    private func determineFeedbackColor() -> Color {
        let lowercasedFeedback = feedbackMessage.lowercased()
        if lowercasedFeedback.contains("ошибка") {
            return .red
        } else if lowercasedFeedback.contains("успешно") || lowercasedFeedback.contains("скопирован") {
            return .green
        }
        return .orange
    }
}

// Add this extension to your EncryptionAlgorithm enum or define it globally
extension EncryptionAlgorithm {
    var isKeyGeneratable: Bool {
        switch self {
        case .rsa, .gost, .fixedPermutation:
            return true
        case .staticEncrypt:
            return false
        }
    }
}

struct KeyGenerationView_Previews: PreviewProvider {
    static var previews: some View {
        KeyGenerationView()
    }
}
