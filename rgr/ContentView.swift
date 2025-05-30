//
//  ContentView.swift
//  rgr
//
//  Created by Stanislav Klepikov on 19.05.2025.
//

import SwiftUI
import SwiftData // Оставляем, как в вашем исходном коде

// Enum для определения типа целевого экрана
enum DestinationViewType {
    case textOperation       // Для экрана операций с текстом
    case fileOperation       // Для экрана операций с файлами
    // Вы можете добавить больше типов, если, например, шифрование и дешифрование
    // будут на совершенно разных экранах, а не режимами одного экрана.
}

struct SidebarItem: Identifiable, Hashable {
    let id = UUID()
    let name: String
    let iconName: String
    let destination: DestinationViewType // Свойство для указания целевого экрана
    let sectionTitle: String // Добавим для возможного использования в заголовке detail view
}

// Определяем элементы боковой панели с указанием их назначения
let sidebarItems: [SidebarItem] = [
    // Секция "Шифрование"
    SidebarItem(name: "Текста", iconName: "note.text", destination: .textOperation, sectionTitle: "Шифрование"),
    SidebarItem(name: "Файлов", iconName: "doc.text", destination: .fileOperation, sectionTitle: "Шифрование"),
    // Секция "Расшифровка"
    SidebarItem(name: "Текста", iconName: "text.viewfinder", destination: .textOperation, sectionTitle: "Расшифровка"),
    SidebarItem(name: "Файлов", iconName: "doc.text.magnifyingglass", destination: .fileOperation, sectionTitle: "Расшифровка")
]

// Для удобства разделения в SidebarView, если хотите сохранить две секции
let encryptItemsList = sidebarItems.filter { $0.sectionTitle == "Шифрование" }
let decryptItemsList = sidebarItems.filter { $0.sectionTitle == "Расшифровка" }


struct ContentView: View {
    @State private var selection: SidebarItem.ID?

    var body: some View {
        NavigationSplitView {
            SidebarView(
                selection: $selection,
                itemsEnc: encryptItemsList,
                sectionTitleEnc: "Шифрование",
                itemsDec: decryptItemsList,
                sectionTitleDec: "Расшифровка"
            )
            .navigationSplitViewColumnWidth(min: 180, ideal: 220, max: 300)
        } detail: {
            if let selectedID = selection,
               let selectedItem = sidebarItems.first(where: { $0.id == selectedID }) {
                
                // Устанавливаем заголовок окна или детального вида
                let viewTitle = "\(selectedItem.sectionTitle): \(selectedItem.name)"
                
                switch selectedItem.destination {
                case .textOperation:
                    TextEncryptDecryptView() // Ваш реализованный экран
                        .navigationTitle(viewTitle) // Устанавливаем заголовок для навигации
                case .fileOperation:
                    FileTransferAndEncryptView() // Ваш реализованный экран
                        .navigationTitle(viewTitle) // Устанавливаем заголовок для навигации
                }
            } else {
              
                Text("Пожалуйста, выберите элемент из боковой панели.")
                    .font(.title2)
                    .foregroundColor(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(minWidth: 700, minHeight: 450) // Немного увеличены минимальные размеры
    }
}

struct SidebarView: View {
    @Binding var selection: SidebarItem.ID?
    let itemsEnc: [SidebarItem]
    let sectionTitleEnc: String
    let itemsDec: [SidebarItem]
    let sectionTitleDec: String

    var body: some View {
        List(selection: $selection) {
            Section(header: Text(sectionTitleEnc).font(.headline)) {
                ForEach(itemsEnc) { item in
                    NavigationLink(value: item.id) {
                        Label(item.name, systemImage: item.iconName)
                    }
                }
            }
            Section(header: Text(sectionTitleDec).font(.headline)) {
                ForEach(itemsDec) { item in
                    NavigationLink(value: item.id) {
                        Label(item.name, systemImage: item.iconName)
                    }
                }
            }
        }
        .listStyle(SidebarListStyle())
    }
}

