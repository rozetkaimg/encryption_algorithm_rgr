//
//  ContentView.swift
//  rgr
//
//  Created by Stanislav Klepikov on 19.05.2025.
//
import SwiftUI
import SwiftData

enum DestinationViewType {
    case textOperation
    case fileOperation
    case keyGeneration
}

struct SidebarItem: Identifiable, Hashable {
    let id = UUID()
    let name: String
    let iconName: String
    let destination: DestinationViewType
    let sectionTitle: String
}

struct SidebarSection: Identifiable {
    let id = UUID()
    let title: String
    let items: [SidebarItem]
}

let sidebarItems: [SidebarItem] = [
    SidebarItem(name: "Текста", iconName: "text.quote", destination: .textOperation, sectionTitle: "Шифрование"),
    SidebarItem(name: "Файлов", iconName: "doc.on.doc", destination: .fileOperation, sectionTitle: "Шифрование"),
    SidebarItem(name: "Генерация Ключей", iconName: "key.fill", destination: .keyGeneration, sectionTitle: "Инструменты")
]

struct ContentView: View {
    @State private var selection: SidebarItem.ID?


    var sections: [SidebarSection] {
        let grouped = Dictionary(grouping: sidebarItems, by: { $0.sectionTitle })
       
        return grouped.map { SidebarSection(title: $0.key, items: $0.value) }
                      .sorted {
                          if $0.title == "Шифрование" { return true }
                          if $1.title == "Шифрование" { return false }
                          return $0.title < $1.title
                      }
    }

    var body: some View {
        NavigationSplitView {
            SidebarView(
                selection: $selection,
                sections: sections 
            )
            .navigationSplitViewColumnWidth(min: 200, ideal: 240, max: 320)
        } detail: {
            if let selectedID = selection,
               let selectedItem = sidebarItems.first(where: { $0.id == selectedID }) {
                
                let viewTitle = "\(selectedItem.sectionTitle): \(selectedItem.name)"
                
                switch selectedItem.destination {
                case .textOperation:
                    TextEncryptDecryptView()
                        .navigationTitle(viewTitle)
                case .fileOperation:
                    FileTransferAndEncryptView()
                        .navigationTitle(viewTitle)
                case .keyGeneration:
                    KeyGenerationView()
                        .navigationTitle(viewTitle)
                }
            } else {
            
                VStack {
                    Image(systemName: "lock.shield.fill")
                        .font(.system(size: 60))
                        .foregroundColor(.accentColor)
                        .padding(.bottom)
                    Text("Криптографические Инструменты")
                        .font(.title)
                        .padding(.bottom, 5)
                    Text("Пожалуйста, выберите операцию из боковой панели.")
                        .font(.title3)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(minWidth: 800, minHeight: 600)
    }
}

struct SidebarView: View {
    @Binding var selection: SidebarItem.ID?
    let sections: [SidebarSection]

    var body: some View {
        List(selection: $selection) {
            ForEach(sections) { section in
                Section(header: Text(section.title).font(.headline)) {
                    ForEach(section.items) { item in
                        NavigationLink(value: item.id) {
                            Label(item.name, systemImage: item.iconName)
                        }
                    }
                }
            }
        }
        .listStyle(SidebarListStyle())
    }
}
