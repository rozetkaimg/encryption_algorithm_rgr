import SwiftUI


struct TextEncryptDecryptView: View {
    @State private var inputText: String = ""
    @State private var outputText: String = ""
    @State private var rsaNKey: String = ""
    @State private var rsaEKey: String = ""
    @State private var rsaDKey: String = ""
    @State private var generalEncryptionKey: String = ""
    @State private var gostInitialIvHex: String = ""
    @State private var permutationKeyString: String = ""

    @State private var selectedAlgorithm: EncryptionAlgorithm = .rsa
    @State private var feedbackMessage: String = "Введите текст для обработки."

    private let rsaWrapper = RSAObjectiveCWrapper()
    private let gostWrapper = GOSTObjectiveCWrapper()
    private let permutationWrapper = PermutationCipherObjectiveCWrapper()

    private var isKeyRequired: Bool {
        switch selectedAlgorithm {
        case .rsa, .gost, .fixedPermutation:
            return true
        case .staticEncrypt:
            return false
        }
    }
    
    private var areRSAKeysProvided: Bool {
        !rsaNKey.isEmpty && !rsaEKey.isEmpty
    }
    private var areRSADecryptionKeysProvided: Bool {
        !rsaNKey.isEmpty && !rsaDKey.isEmpty
    }

    private var isGOSTKeyProvided: Bool {
        !generalEncryptionKey.isEmpty && generalEncryptionKey.count == GOST_KEY_SIZE_BYTES * 2
    }
    private var isGOSTIvProvidedOrCanBeGenerated: Bool {
        gostInitialIvHex.isEmpty || gostInitialIvHex.count == GOST_IV_SIZE_BYTES * 2
    }
    private var isPermutationKeyProvided: Bool {
        !permutationKeyString.isEmpty     }


    var body: some View {
        VStack(spacing: 15) {
            Text("Шифрование с Текстом")
                .font(.largeTitle)
                .padding(.bottom, 10)

            VStack(alignment: .leading) {
                Text("Исходный текст:")
                    .font(.headline)
                TextEditor(text: $inputText)
                    .frame(height: 100)
                    .border(Color.gray.opacity(0.5), width: 1)
                    .clipShape(RoundedRectangle(cornerRadius: 6))
            }

            VStack(alignment: .leading, spacing: 10) {
                Text("Параметры:")
                    .font(.headline)
                
                Picker("Алгоритм:", selection: $selectedAlgorithm) {
                    ForEach(EncryptionAlgorithm.allCases) { algorithm in
                        Text(algorithm.rawValue).tag(algorithm)
                    }
                }
                .onChange(of: selectedAlgorithm) { _ in
                    updateFeedbackForAlgorithmChange()
                }

                if selectedAlgorithm == .rsa {
                    Button("Сгенерировать RSA Ключи (512-бит, демо)") {
                        generateAndSetRSAKeys()
                    }
                    .buttonStyle(.borderedProminent)
                    
                    TextField("RSA N (hex)", text: $rsaNKey).textFieldStyle(RoundedBorderTextFieldStyle())
                    TextField("RSA E (hex, public)", text: $rsaEKey).textFieldStyle(RoundedBorderTextFieldStyle())
                    TextField("RSA D (hex, private)", text: $rsaDKey).textFieldStyle(RoundedBorderTextFieldStyle())
                    Text("Примечание: Ключ D используется для расшифрования.")
                        .font(.caption)
                        .foregroundColor(.gray)

                } else if selectedAlgorithm == .gost {
                    HStack {
                        Button("Сген. ГОСТ Ключ (256-бит)") {
                            generateAndSetGOSTKey()
                        }
                        .buttonStyle(.bordered)
                        Button("Сген. ГОСТ IV (64-бит)") {
                            generateAndSetGOSTIv()
                        }
                        .buttonStyle(.bordered)
                    }
                    SecureField("Ключ ГОСТ (hex, 64 символа)", text: $generalEncryptionKey)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                    TextField("ГОСТ IV (hex, 16 симв., опционально для шифр.)", text: $gostInitialIvHex)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                    Text("Примечание: IV будет сгенерирован если не указан при шифровании.\nДля расшифрования IV извлекается из входных данных ('IV:Ciphertext').")
                         .font(.caption)
                         .foregroundColor(.gray)
                } else if selectedAlgorithm == .fixedPermutation {
                    TextField("Ключ перестановки (например, '201')", text: $permutationKeyString)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                    Text("Ключ - строка цифр 0..N-1 без повторений,\nгде N - длина ключа (размер блока).")
                        .font(.caption)
                        .foregroundColor(.gray)
                } else if selectedAlgorithm == .staticEncrypt {
                }
            }
            .padding(.vertical, 10)

            HStack(spacing: 15) {
                Button(action: processEncrypt) {
                    HStack { Image(systemName: "lock.fill"); Text("Зашифровать") }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .controlSize(.large)
                .disabled(shouldDisableEncryptButton())

                Button(action: processDecrypt) {
                    HStack { Image(systemName: "lock.open.fill"); Text("Расшифровать") }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .controlSize(.large)
                .disabled(shouldDisableDecryptButton())
            }

            VStack(alignment: .leading) {
                HStack {
                    Text("Результат:")
                        .font(.headline)
                    Spacer()
                    if !outputText.isEmpty {
                        Button {
                            copyToClipboard(text: outputText)
                        } label: {
                            Image(systemName: "doc.on.doc")
                            Text("Копировать")
                        }
                        .buttonStyle(.borderless)
                    }
                }
                TextEditor(text: .constant(outputText))
                    .frame(height: 100)
                    .background(Color.secondary.opacity(0.1))
                    .border(Color.gray.opacity(0.5), width: 1)
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                    .textSelection(.enabled)
            }
            
            if !feedbackMessage.isEmpty {
                Text(feedbackMessage)
                    .font(.caption)
                    .foregroundColor(determineFeedbackColor())
                    .padding(.top, 5)
            }
            
            Spacer()
        }
        .padding()
        .frame(minWidth: 500, idealWidth: 600, minHeight: 700, idealHeight: 800)
        .onAppear {
            updateFeedbackForAlgorithmChange()
        }
    }
    
    private func copyToClipboard(text: String) {
        #if os(macOS)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        feedbackMessage = "Результат скопирован в буфер обмена."
        #elseif os(iOS)
        UIPasteboard.general.string = text
        feedbackMessage = "Результат скопирован в буфер обмена."
        #endif
    }
    
    private func shouldDisableEncryptButton() -> Bool {
        if inputText.isEmpty { return true }
        switch selectedAlgorithm {
        case .rsa:
            return !areRSAKeysProvided
        case .gost:
            return !(isGOSTKeyProvided && isGOSTIvProvidedOrCanBeGenerated)
        case .fixedPermutation:
            return !isPermutationKeyProvided
        case .staticEncrypt:
            return false
        }
    }

    private func shouldDisableDecryptButton() -> Bool {
        if inputText.isEmpty { return true }
        switch selectedAlgorithm {
        case .rsa:
            return !areRSADecryptionKeysProvided
        case .gost:
            return !isGOSTKeyProvided || !inputText.contains(":")
        case .fixedPermutation:
            return !isPermutationKeyProvided
        case .staticEncrypt:
            return false
        }
    }
    
    private func generateAndSetRSAKeys() {
        feedbackMessage = "Генерация RSA ключей..."
        DispatchQueue.global(qos: .userInitiated).async {
            let keysString = rsaWrapper.generateRSAKeys(withBits: 512)
            DispatchQueue.main.async {
                if keysString.starts(with: "Error:") {
                    self.feedbackMessage = keysString
                    self.rsaNKey = ""
                    self.rsaEKey = ""
                    self.rsaDKey = ""
                } else {
                    let components = keysString.components(separatedBy: ";")
                    if components.count == 3 {
                        self.rsaNKey = components[0]
                        self.rsaEKey = components[1]
                        self.rsaDKey = components[2]
                        self.feedbackMessage = "RSA ключи (n, e, d) сгенерированы и установлены (hex)."
                    } else {
                        self.feedbackMessage = "Ошибка: Неверный формат сгенерированных RSA ключей."
                        self.rsaNKey = ""
                        self.rsaEKey = ""
                        self.rsaDKey = ""
                    }
                }
                 self.updateFeedbackForAlgorithmChange()
            }
        }
    }

    private func generateAndSetGOSTKey() {
        feedbackMessage = "Генерация ГОСТ ключа..."
        DispatchQueue.global(qos: .userInitiated).async {
            let keyHex = gostWrapper.generateGOSTKeyHex()
            DispatchQueue.main.async {
                if keyHex.starts(with: "Error:") {
                    self.feedbackMessage = keyHex
                    self.generalEncryptionKey = ""
                } else {
                    self.generalEncryptionKey = keyHex
                    self.feedbackMessage = "ГОСТ ключ (256-бит) сгенерирован и установлен (hex)."
                }
                updateFeedbackForAlgorithmChange()
            }
        }
    }

    private func generateAndSetGOSTIv() {
        feedbackMessage = "Генерация ГОСТ IV..."
        DispatchQueue.global(qos: .userInitiated).async {
            let ivHex = gostWrapper.generateGOSTIvHex()
            DispatchQueue.main.async {
                if ivHex.starts(with: "Error:") {
                    self.feedbackMessage = ivHex
                    self.gostInitialIvHex = ""
                } else {
                    self.gostInitialIvHex = ivHex
                    self.feedbackMessage = "ГОСТ IV (64-бит) сгенерирован и установлен (hex)."
                }
                 updateFeedbackForAlgorithmChange()
            }
        }
    }

    private func updateFeedbackForAlgorithmChange() {
        switch selectedAlgorithm {
        case .rsa:
            if !areRSAKeysProvided {
                feedbackMessage = "Для RSA сгенерируйте или введите компоненты ключа (N, E для шифр., N, D для дешифр.)."
            } else if !areRSADecryptionKeysProvided && areRSAKeysProvided {
                 feedbackMessage = "RSA: Ключи N и E указаны (для шифрования). Для дешифрования также нужен ключ D."
            }
            else {
                feedbackMessage = "RSA готово к обработке."
            }
        case .gost:
            var gostMessages: [String] = []
            if !isGOSTKeyProvided {
                gostMessages.append("Требуется ГОСТ ключ (64 hex символа).")
            }
            if gostInitialIvHex.isEmpty {
                 gostMessages.append("IV для шифрования будет сгенерирован автоматически.")
            } else if gostInitialIvHex.count != GOST_IV_SIZE_BYTES * 2 {
                gostMessages.append("ГОСТ IV должен быть \(GOST_IV_SIZE_BYTES*2) hex символов или пуст (для автогенерации).")
            }

            if gostMessages.isEmpty && isGOSTKeyProvided {
                feedbackMessage = "ГОСТ готово к обработке."
            } else if !isGOSTKeyProvided {
                 feedbackMessage = "Для ГОСТ требуется ключ (64 hex символа)."
            }
            else {
                feedbackMessage = gostMessages.joined(separator: " ")
            }
        case .fixedPermutation:
            if permutationKeyString.isEmpty {
                feedbackMessage = "Для Фиксированной Перестановки введите ключ (например, '201')."
            } else {
                feedbackMessage = "Фиксированная Перестановка готова к обработке."
            }
        case .staticEncrypt:
            feedbackMessage = "Для алгоритма «\(selectedAlgorithm.rawValue)» ключ не используется."
        }
    }

    private func determineFeedbackColor() -> Color {
        let lowercasedFeedback = feedbackMessage.lowercased()
        if lowercasedFeedback.contains("ошибка") || lowercasedFeedback.contains("требуется") || lowercasedFeedback.contains("должен быть") {
            return .red
        } else if lowercasedFeedback.contains("успешно") ||
                  lowercasedFeedback.contains("готово") ||
                  lowercasedFeedback.contains("сгенерированы") ||
                  lowercasedFeedback.contains("сгенерирован") ||
                  lowercasedFeedback.contains("скопирован") {
            return .green
        }
        return .orange
    }

    private func processEncrypt() {
        guard !inputText.isEmpty else {
            feedbackMessage = "Ошибка: Исходный текст не может быть пустым."
            return
        }
        outputText = ""

        switch selectedAlgorithm {
        case .staticEncrypt:
            outputText = String(inputText.map { char -> Character in
                if let scalar = char.unicodeScalars.first, scalar.isASCII {
                    let newScalarValue = scalar.value + 1
                    return Character(UnicodeScalar(newScalarValue) ?? scalar)
                }
                return char
            })
            feedbackMessage = "Текст «зашифрован» алгоритмом «\(selectedAlgorithm.rawValue)»."
        case .rsa:
            guard areRSAKeysProvided else {
                feedbackMessage = "Ошибка: Для шифрования RSA требуются ключи N и E."
                return
            }
            feedbackMessage = "RSA шифрование..."
            DispatchQueue.global(qos: .userInitiated).async {
                let result = rsaWrapper.encryptRSA(withPlaintext: inputText, nHex: rsaNKey, eHex: rsaEKey)
                DispatchQueue.main.async {
                    self.outputText = result
                    if result.starts(with: "Error:") {
                        self.feedbackMessage = result
                    } else {
                        self.feedbackMessage = "Текст зашифрован RSA. Результат в HEX."
                    }
                }
            }
        case .gost:
            guard isGOSTKeyProvided else {
                feedbackMessage = "Ошибка: Для ГОСТ требуется ключ (64 hex символа)."
                return
            }
            if !gostInitialIvHex.isEmpty && gostInitialIvHex.count != GOST_IV_SIZE_BYTES * 2 {
                feedbackMessage = "Ошибка: ГОСТ IV должен быть \(GOST_IV_SIZE_BYTES*2) hex символов или пуст."
                return
            }

            feedbackMessage = "ГОСТ шифрование..."
            DispatchQueue.global(qos: .userInitiated).async {
                let ivToUse: String? = self.gostInitialIvHex.isEmpty ? nil : self.gostInitialIvHex
                
                let result = self.gostWrapper.encryptTextGOST(inputText,
                                                              keyHex: self.generalEncryptionKey,
                                                              initialIvHex: ivToUse)
                DispatchQueue.main.async {
                    self.outputText = result
                    if result.starts(with: "Error:") {
                        self.feedbackMessage = result
                    } else {
                        self.feedbackMessage = "Текст зашифрован ГОСТ. Результат в формате 'IV_hex:Ciphertext_hex'."
                    }
                }
            }
        case .fixedPermutation:
            guard isPermutationKeyProvided else {
                feedbackMessage = "Ошибка: Для Фиксированной Перестановки требуется ключ."
                return
            }
            feedbackMessage = "Шифрование Фиксированной Перестановкой..."
            DispatchQueue.global(qos: .userInitiated).async {
                let result = self.permutationWrapper.encryptTextPermutation(self.inputText,
                                                                  keyString: self.permutationKeyString)
                DispatchQueue.main.async {
                    self.outputText = result
                    if result.starts(with: "Error:") {
                        self.feedbackMessage = result
                    } else {
                        self.feedbackMessage = "Текст зашифрован Фиксированной Перестановкой. Результат в HEX."
                    }
                }
            }
        }
    }

    private func processDecrypt() {
        guard !inputText.isEmpty else {
            feedbackMessage = "Ошибка: Текст для дешифрования (в поле исходного текста) не может быть пустым."
            return
        }
        outputText = ""

        switch selectedAlgorithm {
        case .staticEncrypt:
            outputText = String(inputText.map { char -> Character in
                if let scalar = char.unicodeScalars.first, scalar.isASCII {
                    let newScalarValue = scalar.value - 1
                    return Character(UnicodeScalar(newScalarValue) ?? scalar)
                }
                return char
            })
            feedbackMessage = "Текст «расшифрован» алгоритмом «\(selectedAlgorithm.rawValue)»."
        case .rsa:
            guard areRSADecryptionKeysProvided else {
                feedbackMessage = "Ошибка: Для дешифрования RSA требуются ключи N и D."
                return
            }
            feedbackMessage = "RSA дешифрование..."
            DispatchQueue.global(qos: .userInitiated).async {
                let result = rsaWrapper.decryptRSA(withCiphertext: inputText, nHex: rsaNKey, dHex: rsaDKey)
                DispatchQueue.main.async {
                    self.outputText = result
                    if result.starts(with: "Error:") {
                        self.feedbackMessage = result
                    } else {
                        self.feedbackMessage = "Текст расшифрован RSA."
                    }
                }
            }
        case .gost:
            guard isGOSTKeyProvided else {
                feedbackMessage = "Ошибка: Для дешифрования ГОСТ требуется ключ (64 hex символа)."
                return
            }
            guard inputText.contains(":") else {
                feedbackMessage = "Ошибка: Неверный формат для дешифрования ГОСТ. Ожидается 'IV_hex:Ciphertext_hex'."
                return
            }

            feedbackMessage = "ГОСТ дешифрование..."
            DispatchQueue.global(qos: .userInitiated).async {
                let result = self.gostWrapper.decryptTextGOST(self.inputText,
                                                              keyHex: self.generalEncryptionKey)
                DispatchQueue.main.async {
                    self.outputText = result
                    if result.starts(with: "Error:") {
                        self.feedbackMessage = result
                    } else {
                        self.feedbackMessage = "Текст расшифрован ГОСТ."
                    }
                }
            }
        case .fixedPermutation:
            guard isPermutationKeyProvided else {
                feedbackMessage = "Ошибка: Для дешифрования Фиксированной Перестановкой требуется ключ."
                return
            }
            feedbackMessage = "Дешифрование Фиксированной Перестановкой..."
            DispatchQueue.global(qos: .userInitiated).async {
                let result = self.permutationWrapper.decryptTextPermutation(self.inputText,
                                                                  keyString: self.permutationKeyString)
                DispatchQueue.main.async {
                    self.outputText = result
                    if result.starts(with: "Error:") {
                        self.feedbackMessage = result
                    } else {
                        self.feedbackMessage = "Текст расшифрован Фиксированной Перестановкой."
                    }
                }
            }
        }
    }
}

struct TextEncryptDecryptView_Previews: PreviewProvider {
    static var previews: some View {
        TextEncryptDecryptView()
    }
}
