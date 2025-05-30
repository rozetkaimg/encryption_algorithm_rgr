import SwiftUI

struct TextEncryptDecryptView: View {
    @State private var inputText: String = ""
    @State private var outputText: String = ""
    @State private var rsaNKey: String = ""
    @State private var rsaEKey: String = ""
    @State private var rsaDKey: String = ""
    @State private var generalEncryptionKey: String = ""
    @State private var selectedAlgorithm: EncryptionAlgorithm = .rsa
    @State private var feedbackMessage: String = "Введите текст для обработки."

    private let rsaWrapper = RSAObjectiveCWrapper()

    private var isKeyRequired: Bool {
        switch selectedAlgorithm {
        case .rsa, .gost:
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

                } else if isKeyRequired {
                    SecureField("Ключ (для ГОСТ)", text: $generalEncryptionKey)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
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
                    .disabled(true)
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
            return generalEncryptionKey.isEmpty
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
            return generalEncryptionKey.isEmpty
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
                        self.feedbackMessage = "Ошибка: Неверный формат сгенерированных ключей."
                        self.rsaNKey = ""
                        self.rsaEKey = ""
                        self.rsaDKey = ""
                    }
                }
            }
        }
    }

    private func updateFeedbackForAlgorithmChange() {
        switch selectedAlgorithm {
        case .rsa:
            if !areRSAKeysProvided {
                feedbackMessage = "Для RSA сгенерируйте или введите компоненты ключа (N, E)."
            } else {
                feedbackMessage = "RSA готово к обработке."
            }
        case .gost:
            if generalEncryptionKey.isEmpty {
                feedbackMessage = "Для алгоритма «\(selectedAlgorithm.rawValue)» требуется ключ."
            } else {
                feedbackMessage = "ГОСТ готово к обработке."
            }
        case .staticEncrypt:
            feedbackMessage = "Для алгоритма «\(selectedAlgorithm.rawValue)» ключ не используется."
        }
    }

    private func determineFeedbackColor() -> Color {
        if feedbackMessage.lowercased().contains("ошибка") || feedbackMessage.lowercased().contains("требуется") {
            return .red
        } else if feedbackMessage.lowercased().contains("успешно") ||
                    feedbackMessage.lowercased().contains("готово") ||
                    feedbackMessage.lowercased().contains("сгенерированы") ||
                    feedbackMessage.lowercased().contains("скопирован") {
            return .green
        }
        return .orange
    }

    private func processEncrypt() {
        guard !inputText.isEmpty else {
            feedbackMessage = "Ошибка: Исходный текст не может быть пустым."
            return
        }

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
            guard !generalEncryptionKey.isEmpty else {
                feedbackMessage = "Ошибка: Для ГОСТ требуется ключ."
                return
            }
            let prefix = "GOST_ENC(KEY:\(String(repeating: "*", count: generalEncryptionKey.count))): \n"
            let transformedScalars = inputText.unicodeScalars.map {
                UnicodeScalar($0.value + UInt32(generalEncryptionKey.count % 5 + 1)) ?? $0
            }
            outputText = prefix + String(String.UnicodeScalarView(transformedScalars))
            feedbackMessage = "Текст «зашифрован» ГОСТ 28147-89 (имитация)."
        }
    }

    private func processDecrypt() {
        guard !inputText.isEmpty else {
            feedbackMessage = "Ошибка: Текст для дешифрования (в поле исходного текста) не может быть пустым."
            return
        }

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
            guard !generalEncryptionKey.isEmpty else {
                feedbackMessage = "Ошибка: Для ГОСТ требуется ключ."
                return
            }
            let prefix = "GOST_ENC(KEY:\(String(repeating: "*", count: generalEncryptionKey.count))): \n"
            if inputText.hasPrefix(prefix) {
                let relevantText = String(inputText.dropFirst(prefix.count))
                let transformedScalars = relevantText.unicodeScalars.map {
                    UnicodeScalar($0.value - UInt32(generalEncryptionKey.count % 5 + 1)) ?? $0
                }
                outputText = String(String.UnicodeScalarView(transformedScalars))
                feedbackMessage = "Текст «расшифрован» ГОСТ 28147-89 (имитация)."
            } else {
                outputText = ""
                feedbackMessage = "Ошибка: Неверный формат для дешифрования ГОСТ (имитация)."
            }
        }
    }
}



struct TextEncryptDecryptView_Previews: PreviewProvider {
    static var previews: some View {
        TextEncryptDecryptView()
    }
}
