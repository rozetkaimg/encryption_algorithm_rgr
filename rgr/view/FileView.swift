import SwiftUI
import UniformTypeIdentifiers

struct FileTransferAndEncryptView: View {
    
    @State private var sourceFileURL: URL?
    @State private var isDropTargeted: Bool = false
    @State private var selectedAlgorithm: EncryptionAlgorithm = .rsa
    @State private var outputProcessedURL: URL?
    @State private var isProcessing: Bool = false
    
    @State private var rsaNKey: String = ""
    @State private var rsaEKey: String = ""
    @State private var rsaDKey: String = ""
    
    @State private var gostKeyHex: String = ""
    @State private var gostInitialIvHex: String = ""
    
    private let rsaWrapper = RSAObjectiveCWrapper()
    private let gostWrapper = GOSTObjectiveCWrapper()
    
    @State private var feedbackMessage: String = "Ожидание файла..."
    
    var body: some View {
        VStack(spacing: 20) {
            Text("Обработка Файлов")
                .font(.largeTitle)
                .padding(.bottom, 10)
            
            HStack(spacing: 20) {
                dropZoneContainer
                    .frame(maxWidth: .infinity, maxHeight: 220)
                
                Divider().frame(height: 200)
                
                dragSourceView
                    .frame(maxWidth: .infinity, maxHeight: 220)
            }
            .padding(.horizontal)
            
            Divider()
            
            encryptionControlsView
                .padding(.horizontal)
            
            if isProcessing {
                ProgressView()
                    .padding(.top, 5)
            }
            
            if !feedbackMessage.isEmpty {
                Text(feedbackMessage)
                    .font(.caption)
                    .foregroundColor(determineFeedbackColor())
                    .padding(.top, 5)
                    .frame(maxWidth: .infinity, alignment: .center)
                    .lineLimit(4)
                    .multilineTextAlignment(.center)
            }
        }
        .padding()
        .frame(minWidth: 650, idealWidth: 700, minHeight: 650, idealHeight: 700)
        .onAppear(perform: updateFeedbackForAlgorithmChange)
        .onDisappear(perform: cleanupTemporaryFile)
    }
    
    private var dropZoneContainer: some View {
        VStack(spacing: 10) {
            Text("1. Выберите исходный файл:")
                .font(.headline)
                .frame(maxWidth: .infinity, alignment: .leading)
            
            dropZoneView
                .frame(minHeight: 120)
            
            Button {
                showOpenPanel()
            } label: {
                HStack {
                    Image(systemName: "doc.badge.plus")
                    Text("Выбрать файл из Finder")
                }
            }
            .controlSize(.large)
        }
    }
    
    private var encryptionControlsView: some View {
        VStack(alignment: .leading, spacing: 15) {
            Text("2. Параметры обработки:")
                .font(.title2)
            
            Picker("Алгоритм:", selection: $selectedAlgorithm) {
                ForEach(EncryptionAlgorithm.allCases) { algorithm in
                    Text(algorithm.rawValue).tag(algorithm)
                }
            }
            .padding(.horizontal)
            .onChange(of: selectedAlgorithm) { _ in
                updateFeedbackForAlgorithmChange()
                cleanupTemporaryFile()
            }
            
            if selectedAlgorithm == .rsa {
                Group {
                    Button("Сгенерировать RSA Ключи (512-бит, демо)") {
                        generateAndSetRSAKeys()
                    }
                    .buttonStyle(.bordered)
                    
                    TextField("RSA N (hex)", text: $rsaNKey).textFieldStyle(RoundedBorderTextFieldStyle())
                    TextField("RSA E (hex, public)", text: $rsaEKey).textFieldStyle(RoundedBorderTextFieldStyle())
                    TextField("RSA D (hex, private)", text: $rsaDKey).textFieldStyle(RoundedBorderTextFieldStyle())
                }
                .padding(.horizontal)
            } else if selectedAlgorithm == .gost {
                Group {
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
                    SecureField("Ключ ГОСТ (hex, 64 симв.)", text: $gostKeyHex)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                    TextField("ГОСТ IV (hex, 16 симв., опционально для шифр.)", text: $gostInitialIvHex)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                    Text("IV будет сгенерирован, если не указан при шифровании.\nДля расшифрования IV считывается из начала файла.")
                        .font(.caption2).foregroundColor(.gray)
                }
                .padding(.horizontal)
            }
            
            HStack(spacing: 15) {
                Button(action: performEncrypt) {
                    HStack {
                        Image(systemName: "lock.fill")
                        Text("Зашифровать")
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(shouldDisableProcessButton())
                .tint(.accentColor)
                
                Button(action: performDecrypt) {
                    HStack {
                        Image(systemName: "lock.open.fill")
                        Text("Расшифровать")
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(shouldDisableProcessButton(isDecrypting: true))
                .tint(.green)
            }
            .padding(.top, 10)

            Button(action: performSave) {
                HStack {
                    Image(systemName: "square.and.arrow.down.fill")
                    Text("Сохранить обработанный файл")
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .controlSize(.large)
            .disabled(outputProcessedURL == nil || isProcessing)
            .padding(.top, 5)

        }
        .padding()
        .background(Color.secondary.opacity(0.05))
        .cornerRadius(10)
    }
    
    private var dropZoneView: some View {
        VStack {
            Image(systemName: "arrow.down.doc.fill")
                .font(.system(size: 30))
                .padding(.bottom, 2)
            Text("Перетащите файл сюда")
                .font(.subheadline)
                .multilineTextAlignment(.center)
        }
        .padding(10)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(isDropTargeted ? Color.blue.opacity(0.2) : Color.secondary.opacity(0.1))
        .cornerRadius(10)
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(isDropTargeted ? Color.blue : Color.gray,
                        style: StrokeStyle(lineWidth: 2, dash: isDropTargeted ? [] : [5, 5]))
        )
        .onDrop(of: [UTType.fileURL], isTargeted: $isDropTargeted) { providers in
            handleFileDrop(providers: providers)
        }
    }
    
    private var dragSourceView: some View {
        VStack(spacing: 10) {
            Text("3. Обработанный файл:")
                .font(.headline)
                .frame(maxWidth: .infinity, alignment: .leading)
            
            Group {
                if let url = outputProcessedURL {
                    VStack {
                        Image(systemName: "checkmark.doc.fill")
                            .font(.system(size: 30))
                            .foregroundColor(.blue)
                            .padding(.bottom, 2)
                        Text(url.lastPathComponent)
                            .font(.caption)
                            .lineLimit(2)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal, 5)
                        Text("(можно перетащить или сохранить)")
                            .font(.caption2)
                            .foregroundColor(.gray)
                    }
                } else {
                    VStack {
                        Image(systemName: "doc.questionmark.fill")
                            .font(.system(size: 30))
                            .foregroundColor(.gray.opacity(0.7))
                            .padding(.bottom, 2)
                        Text(sourceFileURL != nil && !isProcessing ? "Файл готов к обработке" : "Результат обработки появится здесь")
                            .font(.subheadline)
                            .foregroundColor(.gray)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal)
                    }
                }
            }
            .padding(10)
            .frame(maxWidth: .infinity, minHeight: 120, maxHeight: .infinity)
            .background(Color.secondary.opacity(0.05))
            .cornerRadius(10)
            .if(outputProcessedURL != nil) { view in
                view.draggable(outputProcessedURL!) {
                    VStack {
                        Image(systemName: "doc.fill")
                        Text(outputProcessedURL!.lastPathComponent)
                    }
                    .padding(10)
                    .background(Material.regular)
                    .cornerRadius(8)
                    .shadow(radius: 3)
                }
            }
            Spacer().frame(height: 36)
        }
    }
    
    private func determineFeedbackColor() -> Color {
        let lowercasedFeedback = feedbackMessage.lowercased()
        if lowercasedFeedback.contains("ошибка") || lowercasedFeedback.contains("не выбран") || lowercasedFeedback.contains("отменен") || lowercasedFeedback.contains("требуется") || lowercasedFeedback.contains("неверный") || lowercasedFeedback.contains("не найден"){
            return .red
        } else if lowercasedFeedback.contains("успешно") || lowercasedFeedback.contains("готов к сохранению") {
            return .green
        } else if lowercasedFeedback.contains("готов к обработке") || lowercasedFeedback.contains("ключи введены") || lowercasedFeedback.contains("ключи сгенерированы") || lowercasedFeedback.contains("ключ сгенерирован") || lowercasedFeedback.contains("iv сгенерирован") {
            return .blue
        }
        return .orange
    }
    
    private func updateFeedbackForAlgorithmChange() {
        var baseMessage = ""
        switch selectedAlgorithm {
        case .rsa:
            if rsaNKey.isEmpty || rsaEKey.isEmpty {
                baseMessage = "Для RSA сгенерируйте или введите ключи N и E (и D для расшифрования)."
            } else {
                baseMessage = sourceFileURL == nil ? "RSA ключи введены. Выберите файл." : "RSA готово к обработке файла."
            }
        case .gost:
            if gostKeyHex.isEmpty || gostKeyHex.count != GOST_KEY_SIZE_BYTES * 2 {
                baseMessage = "Для ГОСТ введите или сгенерируйте ключ (\(GOST_KEY_SIZE_BYTES * 2) hex симв.)."
            } else if !gostInitialIvHex.isEmpty && gostInitialIvHex.count != GOST_IV_SIZE_BYTES * 2 {
                 baseMessage = "ГОСТ IV должен быть \(GOST_IV_SIZE_BYTES*2) hex символов или пуст (для автогенерации)."
            }
            else {
                baseMessage = sourceFileURL == nil ? "ГОСТ ключ введен. Выберите файл." : "ГОСТ готово к обработке файла."
                if gostInitialIvHex.isEmpty && sourceFileURL != nil {
                     baseMessage += " IV будет сгенерирован."
                }
            }
        case .staticEncrypt:
            baseMessage = sourceFileURL == nil ? "Статический сдвиг. Выберите файл." : "Статический сдвиг готов к обработке файла."
        }
        
        if sourceFileURL != nil && outputProcessedURL == nil && !isProcessing {
            feedbackMessage = baseMessage + " Нажмите Зашифровать/Расшифровать."
        } else if outputProcessedURL != nil && !isProcessing {
            feedbackMessage = "Файл обработан и готов к сохранению."
        } else if !isProcessing {
            feedbackMessage = baseMessage
        }
    }
    
    private func cleanupTemporaryFile() {
        if let tempURL = outputProcessedURL {
            if FileManager.default.fileExists(atPath: tempURL.path) && tempURL.path.contains(FileManager.default.temporaryDirectory.path) {
                try? FileManager.default.removeItem(at: tempURL)
            }
        }
        outputProcessedURL = nil
    }

    private func resetStateForNewFile() {
        cleanupTemporaryFile()
        sourceFileURL = nil
        feedbackMessage = "Ожидание файла..."
        updateFeedbackForAlgorithmChange()
    }
    
    private func showOpenPanel() {
        cleanupTemporaryFile()
        let openPanel = NSOpenPanel()
        openPanel.canChooseFiles = true
        openPanel.canChooseDirectories = false
        openPanel.allowsMultipleSelection = false
        
        if openPanel.runModal() == .OK {
            if let url = openPanel.url {
                processSelectedFile(url: url)
            } else {
                feedbackMessage = "Ошибка: Не удалось получить URL выбранного файла."
            }
        } else {
            feedbackMessage = "Выбор файла отменен."
        }
    }
    
    private func processSelectedFile(url: URL) {
        cleanupTemporaryFile()
        var isDirectory: ObjCBool = false
        if FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory) {
            if isDirectory.boolValue {
                self.feedbackMessage = "Ошибка: Выбор папок не поддерживается."
                self.sourceFileURL = nil
            } else {
                self.sourceFileURL = url
                self.feedbackMessage = "Файл '\(url.lastPathComponent)' выбран. "
                updateFeedbackForAlgorithmChange()
            }
        } else {
            if url.startAccessingSecurityScopedResource() {
                self.sourceFileURL = url
                self.feedbackMessage = "Файл '\(url.lastPathComponent)' выбран (доступ получен). "
                updateFeedbackForAlgorithmChange()
            } else {
                self.sourceFileURL = nil
                self.feedbackMessage = "Ошибка: Не удалось получить доступ к файлу или файл не существует."
            }
        }
    }
    
    private func handleFileDrop(providers: [NSItemProvider]) -> Bool {
        cleanupTemporaryFile()
        guard let provider = providers.first else {
            feedbackMessage = "Ошибка: Провайдер файла не найден."
            return false
        }
        feedbackMessage = "Обработка перетащенного файла..."
        
        if provider.canLoadObject(ofClass: URL.self) {
            _ = provider.loadObject(ofClass: URL.self) { object, error in
                DispatchQueue.main.async {
                    if let error = error {
                        self.feedbackMessage = "Ошибка загрузки URL объекта: \(error.localizedDescription)"
                        self.sourceFileURL = nil
                        return
                    }
                    guard let url = object as? URL else {
                        self.feedbackMessage = "Ошибка: Загруженный объект не является URL."
                        self.sourceFileURL = nil
                        return
                    }
                    guard url.isFileURL else {
                        self.feedbackMessage = "Ошибка: Загруженный URL не является файловым URL (схема: \(url.scheme ?? "нет"))."
                        self.sourceFileURL = nil
                        return
                    }
                    self.processSelectedFile(url: url)
                }
            }
            return true
        }
        else if provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
            provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { (item, error) in
                DispatchQueue.main.async {
                    if let error = error {
                        self.feedbackMessage = "Ошибка загрузки item (тип fileURL): \(error.localizedDescription)"
                        self.sourceFileURL = nil
                        return
                    }
                    
                    var successfullyExtractedURL: URL? = nil
                    
                    if let url = item as? URL {
                        if url.isFileURL {
                            successfullyExtractedURL = url
                        } else {
                            self.feedbackMessage = "Ошибка: Переданный item (URL) не является файловым URL."
                        }
                    } else if let data = item as? Data {
                        do {
                            var isStale = false
                            let resolvedURL = try URL(resolvingBookmarkData: data,
                                                      options: .withSecurityScope,
                                                      relativeTo: nil,
                                                      bookmarkDataIsStale: &isStale)
                            if resolvedURL.isFileURL {
                                successfullyExtractedURL = resolvedURL
                            } else {
                                self.feedbackMessage = "Ошибка: URL, разрешенный из закладки, не является файловым URL."
                            }
                        } catch {
                            if let urlString = String(data: data, encoding: .utf8),
                               let parsedURL = URL(string: urlString),
                               parsedURL.isFileURL {
                                successfullyExtractedURL = parsedURL
                            } else {
                                let bookmarkErrorDescription = error.localizedDescription
                                self.feedbackMessage = "Ошибка: Не удалось преобразовать Data в URL (ни как закладку: \(bookmarkErrorDescription), ни как строку)."
                            }
                        }
                    } else if let urlPath = item as? String,
                              let parsedURL = URL(string: urlPath) {
                        if parsedURL.isFileURL {
                            successfullyExtractedURL = parsedURL
                        } else {
                            self.feedbackMessage = "Ошибка: Строковый путь/URL не является файловым URL."
                        }
                    }
                    
                    if let finalURL = successfullyExtractedURL {
                        self.processSelectedFile(url: finalURL)
                    } else {
                        if self.feedbackMessage == "Обработка перетащенного файла..." || self.feedbackMessage.contains("Ошибка загрузки item (тип fileURL)") {
                            self.feedbackMessage = "Ошибка: Не удалось получить корректный файловый URL. Тип элемента: \(String(describing: type(of: item)))."
                        }
                        self.sourceFileURL = nil
                    }
                }
            }
            return true
        }
        
        self.feedbackMessage = "Ошибка: Неподдерживаемый тип для перетаскивания. Убедитесь, что перетаскивается файл."
        return false
    }
    
    private func shouldDisableProcessButton(isDecrypting: Bool = false) -> Bool {
        if sourceFileURL == nil { return true }
        if isProcessing { return true }
        
        switch selectedAlgorithm {
        case .rsa:
            if rsaNKey.isEmpty { return true }
            return isDecrypting ? rsaDKey.isEmpty : rsaEKey.isEmpty
        case .gost:
            if gostKeyHex.isEmpty || gostKeyHex.count != GOST_KEY_SIZE_BYTES * 2 { return true }
            if !isDecrypting && !gostInitialIvHex.isEmpty && gostInitialIvHex.count != GOST_IV_SIZE_BYTES * 2 { return true }
            return false
        case .staticEncrypt:
            return false
        }
    }
    
    private func generateAndSetRSAKeys() {
        feedbackMessage = "Генерация RSA ключей (512-бит)..."
        isProcessing = true
        DispatchQueue.global(qos: .userInitiated).async {
            let keysString = rsaWrapper.generateRSAKeys(withBits: 512)
            DispatchQueue.main.async {
                self.isProcessing = false
                if keysString.starts(with: "Error:") {
                    self.feedbackMessage = keysString
                    self.rsaNKey = ""; self.rsaEKey = ""; self.rsaDKey = ""
                } else {
                    let components = keysString.components(separatedBy: ";")
                    if components.count == 3 {
                        self.rsaNKey = components[0]
                        self.rsaEKey = components[1]
                        self.rsaDKey = components[2]
                        self.feedbackMessage = "RSA ключи сгенерированы. "
                        self.updateFeedbackForAlgorithmChange()
                    } else {
                        self.feedbackMessage = "Ошибка: Неверный формат сгенерированных RSA ключей."
                        self.rsaNKey = ""; self.rsaEKey = ""; self.rsaDKey = ""
                    }
                }
            }
        }
    }

    private func generateAndSetGOSTKey() {
        feedbackMessage = "Генерация ГОСТ ключа (256-бит)..."
        isProcessing = true
        DispatchQueue.global(qos: .userInitiated).async {
            let keyHex = gostWrapper.generateGOSTKeyHex()
            DispatchQueue.main.async {
                self.isProcessing = false
                if keyHex.starts(with: "Error:") {
                    self.feedbackMessage = keyHex
                    self.gostKeyHex = ""
                } else {
                    self.gostKeyHex = keyHex
                    self.feedbackMessage = "ГОСТ ключ сгенерирован. "
                }
                self.updateFeedbackForAlgorithmChange()
            }
        }
    }

    private func generateAndSetGOSTIv() {
        feedbackMessage = "Генерация ГОСТ IV (64-бит)..."
        isProcessing = true
        DispatchQueue.global(qos: .userInitiated).async {
            let ivHex = gostWrapper.generateGOSTIvHex()
            DispatchQueue.main.async {
                self.isProcessing = false
                if ivHex.starts(with: "Error:") {
                    self.feedbackMessage = ivHex
                    self.gostInitialIvHex = ""
                } else {
                    self.gostInitialIvHex = ivHex
                    self.feedbackMessage = "ГОСТ IV сгенерирован. "
                }
                self.updateFeedbackForAlgorithmChange()
            }
        }
    }

    private func createTemporaryURL(for originalURL: URL, operation: String) -> URL {
        let tempDirectoryURL = FileManager.default.temporaryDirectory
        let uniqueFilenamePart = UUID().uuidString
        let originalFilename = originalURL.deletingPathExtension().lastPathComponent
        var pathExtension = originalURL.pathExtension
        
        if operation == "encrypted_rsa" && pathExtension.isEmpty {
            pathExtension = "enc"
        } else if operation == "encrypted_gost" && pathExtension.isEmpty {
             pathExtension = "gst"
        }


        let tempFilename = "\(originalFilename)_\(operation)_\(uniqueFilenamePart).\(pathExtension)"
        return tempDirectoryURL.appendingPathComponent(tempFilename)
    }
    
    private func performEncrypt() {
        guard let currentSourceURL = sourceFileURL else {
            feedbackMessage = "Файл не выбран для шифрования."
            return
        }
        
        cleanupTemporaryFile()
        let tempOpName = selectedAlgorithm == .rsa ? "encrypted_rsa" : (selectedAlgorithm == .gost ? "encrypted_gost" : "encrypted_static")
        let temporaryDestinationURL = createTemporaryURL(for: currentSourceURL, operation: tempOpName)
        
        self.feedbackMessage = "Шифрование файла '\(currentSourceURL.lastPathComponent)'..."
        self.isProcessing = true
        
        DispatchQueue.global(qos: .userInitiated).async {
            var operationResultMessage: String = ""

            switch self.selectedAlgorithm {
            case .rsa:
                operationResultMessage = self.rsaWrapper.encryptFileRSA(
                    currentSourceURL.path,
                    toOutputFile: temporaryDestinationURL.path,
                    nHex: self.rsaNKey,
                    eHex: self.rsaEKey
                )
            case .gost:
                let ivToUse: String? = self.gostInitialIvHex.isEmpty ? nil : self.gostInitialIvHex
                operationResultMessage = self.gostWrapper.encryptFileGOST(
                    currentSourceURL.path,
                    toOutputFile: temporaryDestinationURL.path,
                    keyHex: self.gostKeyHex,
                    initialIvHex: ivToUse
                )
            case .staticEncrypt:
                do {
                    var data = try Data(contentsOf: currentSourceURL)
                    data = Data(data.map { $0 &+ 1 })
                    try data.write(to: temporaryDestinationURL)
                    operationResultMessage = "Файл успешно зашифрован статическим сдвигом."
                } catch {
                    operationResultMessage = "Error: Ошибка статического шифрования - \(error.localizedDescription)"
                }
            }
            
            let success = !operationResultMessage.lowercased().starts(with: "error:")
            
            DispatchQueue.main.async {
                self.isProcessing = false
                self.feedbackMessage = operationResultMessage + (success ? " Готов к сохранению." : "")
                if success {
                    self.outputProcessedURL = temporaryDestinationURL
                }
                 currentSourceURL.stopAccessingSecurityScopedResourceIfNeeded()
            }
        }
    }
    
    private func performDecrypt() {
        guard let currentSourceURL = sourceFileURL else {
            feedbackMessage = "Зашифрованный файл не выбран для расшифрования."
            return
        }
        
        cleanupTemporaryFile()
        let tempOpName = selectedAlgorithm == .rsa ? "decrypted_rsa" : (selectedAlgorithm == .gost ? "decrypted_gost" : "decrypted_static")
        let temporaryDestinationURL = createTemporaryURL(for: currentSourceURL, operation: tempOpName)

        self.feedbackMessage = "Расшифрование файла '\(currentSourceURL.lastPathComponent)'..."
        self.isProcessing = true
        
        DispatchQueue.global(qos: .userInitiated).async {
            var operationResultMessage: String = ""

            switch self.selectedAlgorithm {
            case .rsa:
                operationResultMessage = self.rsaWrapper.decryptFileRSA(
                    currentSourceURL.path,
                    toOutputFile: temporaryDestinationURL.path,
                    nHex: self.rsaNKey,
                    dHex: self.rsaDKey
                )
            case .gost:
                operationResultMessage = self.gostWrapper.decryptFileGOST(
                    currentSourceURL.path,
                    toOutputFile: temporaryDestinationURL.path,
                    keyHex: self.gostKeyHex
                )
            case .staticEncrypt:
                do {
                    var data = try Data(contentsOf: currentSourceURL)
                    data = Data(data.map { $0 &- 1 })
                    try data.write(to: temporaryDestinationURL)
                    operationResultMessage = "Файл успешно расшифрован статическим сдвигом."
                } catch {
                    operationResultMessage = "Error: Ошибка статического расшифрования - \(error.localizedDescription)"
                }
            }
            
            let success = !operationResultMessage.lowercased().starts(with: "error:")

            DispatchQueue.main.async {
                self.isProcessing = false
                self.feedbackMessage = operationResultMessage + (success ? " Готов к сохранению." : "")
                if success {
                    self.outputProcessedURL = temporaryDestinationURL
                }
                currentSourceURL.stopAccessingSecurityScopedResourceIfNeeded()
            }
        }
    }

    private func performSave() {
        guard let processedFileURL = outputProcessedURL else {
            feedbackMessage = "Нет обработанного файла для сохранения."
            return
        }

        let savePanel = NSSavePanel()
        savePanel.canCreateDirectories = true
        
        let fileNameParts = processedFileURL.deletingPathExtension().lastPathComponent.components(separatedBy: "_")
        var suggestedName = processedFileURL.lastPathComponent
        if fileNameParts.count > 2 { // originalName_operation_uuid
            let originalName = fileNameParts.dropLast(2).joined(separator: "_")
            suggestedName = originalName + "." + processedFileURL.pathExtension
        }
        
        savePanel.nameFieldStringValue = suggestedName


        savePanel.begin { response in
            if response == .OK, let userChosenURL = savePanel.url {
                self.isProcessing = true
                self.feedbackMessage = "Сохранение файла..."
                DispatchQueue.global(qos: .userInitiated).async {
                    do {
                        if FileManager.default.fileExists(atPath: processedFileURL.path) {
                            if FileManager.default.fileExists(atPath: userChosenURL.path) {
                                try FileManager.default.removeItem(at: userChosenURL)
                            }
                            try FileManager.default.copyItem(at: processedFileURL, to: userChosenURL)
                            DispatchQueue.main.async {
                                self.isProcessing = false
                                self.feedbackMessage = "Файл успешно сохранен: \(userChosenURL.lastPathComponent)"
                                self.cleanupTemporaryFile()
                                self.updateFeedbackForAlgorithmChange()
                            }
                        } else {
                            DispatchQueue.main.async {
                                self.isProcessing = false
                                self.feedbackMessage = "Ошибка: Временный обработанный файл не найден."
                            }
                        }
                    } catch {
                        DispatchQueue.main.async {
                            self.isProcessing = false
                            self.feedbackMessage = "Ошибка сохранения файла: \(error.localizedDescription)"
                        }
                    }
                }
            } else {
                self.feedbackMessage = "Сохранение файла отменено."
            }
        }
    }
}

extension URL {
    func stopAccessingSecurityScopedResourceIfNeeded() {
        // For sandboxed apps, you might need to stop accessing security-scoped resources.
        // This is a placeholder; actual implementation depends on how access was started.
        // If you used `startAccessingSecurityScopedResource()`, you should balance it with `stopAccessingSecurityScopedResource()`.
        // However, for file drops and NSOpenPanel, the system often manages this.
        // If this URL was obtained via startAccessingSecurityScopedResource, uncomment:
        // self.stopAccessingSecurityScopedResource()
    }
}


extension View {
    @ViewBuilder
    func `if`<Content: View>(_ condition: Bool, transform: (Self) -> Content) -> some View {
        if condition {
            transform(self)
        } else {
            self
        }
    }
}

struct FileTransferAndEncryptView_Previews: PreviewProvider {
    static var previews: some View {
        FileTransferAndEncryptView()
    }
}

