//
//  ContentView.swift
//  ventusdemo
//
//  Created by Omar Mohamed on 2025-06-23.
//

import SwiftUI
import LocalAuthentication
import PhotosUI
import CryptoKit
import Foundation
import Swoir
import Swoirenberg
//import MoproFFI


struct ContentView: View {
    @State private var isUnlocked = false
    @State private var selectedItem: PhotosPickerItem? = nil
    @State private var selectedImage: UIImage? = nil
    @State private var message: String = ""
    @State private var isProcessing = false
    @State private var showingCamera = false
    
    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                // 🔖 App Title
                Text("Ventus Demo")
                    .font(.largeTitle)
                    .bold()
                    .padding(.top)
            }
            VStack(spacing: 24) {

                // 🔐 Unlocked View
                if isUnlocked {
                    
                    // 📷 Display selected image if available
                    if let image = selectedImage {
                        Image(uiImage: image)
                            .resizable()
                            .scaledToFit()
                            .frame(height: 300)
                            .cornerRadius(12)
                            .shadow(radius: 4)

                        // 🔐 Generate Proof Button
                        Button(action: {
                            generateProof(image: image)
                        }) {
                            Label("Generate Proof", systemImage: "arrow.triangle.2.circlepath")
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(isProcessing)
                        .controlSize(.large)
                    }

                    // 📸 Take Photo Button (always shown)
                    Button(action: {
                        showingCamera = true
                    }) {
                        Label("Take Photo", systemImage: "camera")
                    }
                    .buttonStyle(.borderedProminent)

                    // 🖼️ Pick from Photo Library
                    PhotosPicker(
                        selection: $selectedItem,
                        matching: .images,
                        photoLibrary: .shared()
                    ) {
                        Label("Pick a Photo", systemImage: "photo")
                    }
                    .buttonStyle(.borderedProminent)

                    // 💬 Show message (e.g. signature output)
                    if !message.isEmpty {
                        ScrollView {
                            Text(message)
                                .font(.callout)
                                .foregroundColor(.gray)
                                .padding()
                                .textSelection(.enabled) // allow copy/paste
                        }
                    }

                } else {
                    // 🔓 Face ID Unlock Button
                    Button(action: authenticate) {
                        Label("Unlock with Face ID", systemImage: "faceid")
                    }
                    .buttonStyle(.borderedProminent)
                }

                Spacer()
            }
            .padding()
            .onChange(of: selectedItem) { newItem in
                if let newItem {
                    loadImage(from: newItem)
                }
            }
        }
        // 📸 Show Camera Sheet
        .sheet(isPresented: $showingCamera) {
            CameraPicker { image in
                self.showingCamera = false
                self.selectedImage = image
                self.generateProof(image: image);
            }
        }
    }

    func authenticate() {
        let context = LAContext()
        var error: NSError?
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Unlock app") { success, _ in
                DispatchQueue.main.async {
                    isUnlocked = success
                }
            }
        } else {
            message = "Biometric authentication not available."
        }
    }
    
    
    func loadImage(from item: PhotosPickerItem) {
        isProcessing = true
        message = ""
        Task {
            if let data = try? await item.loadTransferable(type: Data.self),
               let uiImage = UIImage(data: data) {
                await MainActor.run {
                    selectedImage = uiImage
                    generateProof(image:uiImage);
                }
            } else {
                await MainActor.run {
                    message = "Failed to load image."
                }
            }
            isProcessing = false
        }
    }
    
    func generateProof(image: UIImage) {
        signImage(image) { signature, pubkeyData in
            guard let sig = signature,
                  let pk = pubkeyData,
                  let rawSig = derToRawSignature(sig),
                  let (x, y) = splitPubkey(pk),
                  let imageData = image.jpegData(compressionQuality: 1) else {
                DispatchQueue.main.async {
                    self.message = "❌ Failed to prepare ZK inputs."
                }
                return
            }

            let hash = SHA256.hash(data: imageData)
            let hashBytes = [UInt8](hash)

            do {
                let verified = try runZKProof(
                    //uncomment these
                    pubKeyX: x,
                    pubKeyY: y,
                    signature: rawSig,
                    hash: hashBytes
                )}

                DispatchQueue.main.async {
                    self.message = "✅ Proof Ready!"
            } catch {
                DispatchQueue.main.async {
                    self.message = "❌ Failed to generate witness: \(error)"
                }
            }
        }
    }

    
    func signImage(_ image: UIImage, completion: @escaping (Data?, Data?) -> Void) {
        guard let imageData = image.jpegData(compressionQuality: 1) else {
            message = "Failed to get image data."
            completion(nil, nil)
            return
        }

        let hash = SHA256.hash(data: imageData)
        message = "Image hashed: \(hash.map { String(format: "%02x", $0) }.joined())"
        let hashData = Data(hash)

        signWithSecureEnclave(data: hashData) { signature in
            DispatchQueue.main.async {
                guard let sig = signature,
                      let privateKey = getSecureEnclavePrivateKey(),
                      let pubkey = SecKeyCopyPublicKey(privateKey),
                      let pubkeyData = SecKeyCopyExternalRepresentation(pubkey, nil) as Data? else {
                    self.message = "Failed to sign image."
                    completion(nil, nil)
                    return
                }

                self.message = "✅ Signature ready!"
                completion(sig, pubkeyData)
            }
        }
    }

    func signWithSecureEnclave(data: Data, completion: @escaping (Data?) -> Void) {
        guard let privateKey = getSecureEnclavePrivateKey() else {
            print("No private key available")
            completion(nil)
            return
        }
        
        let context = LAContext()
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Sign data") { success, error in
            guard success else {
                print("Authentication failed")
                completion(nil)
                return
            }
            
            let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
            
            guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
                print("Algorithm not supported")
                completion(nil)
                return
            }
            
            var error: Unmanaged<CFError>?
            if let signature = SecKeyCreateSignature(privateKey, algorithm, data as CFData, &error) as Data? {
                completion(signature)
            } else {
                print("Signing failed: \(error?.takeRetainedValue().localizedDescription ?? "unknown error")")
                completion(nil)
            }
        }
    }
    
    func splitPubkey(_ keydata: Data) -> (x: [UInt8], y: [UInt8])?{
        guard keydata.count == 65, keydata[0] == 0x04 else{
            return nil
        }
        let x = Array(keydata[1..<33])
        let y = Array(keydata[33..<65])
        return (x,y)
    }
    
    func printPubkey() -> String{
        guard let pk = getSecureEnclavePrivateKey() else {
            return "Failed to get Pubkey!"
        }
        let pubkey = SecKeyCopyPublicKey(pk)!
        if let publicKeyData = SecKeyCopyExternalRepresentation(pubkey, nil) as Data? {
               let base64Key = publicKeyData.base64EncodedString()
               return "🔑 Public Key (Base64):\n\(base64Key)"
           } else {
               return "❌ Failed to export public key data"
           }
       }
    
    func extractRawPublicKey(_ secKey: SecKey) -> Data? {
        var error: Unmanaged<CFError>?
        guard let keyData = SecKeyCopyExternalRepresentation(secKey, &error) as Data? else {
            print("Error exporting key:", error?.takeRetainedValue())
            return nil
        }
        return keyData
    }
    func derToRawSignature(_ der: Data) -> [UInt8]? {
        let bytes = [UInt8](der)
        guard bytes.count > 8, bytes[0] == 0x30 else { return nil }

        var index = 2
        guard bytes[index] == 0x02 else { return nil }
        let rLen = Int(bytes[index + 1])
        var r = Array(bytes[(index + 2)..<(index + 2 + rLen)])
        index += 2 + rLen

        guard bytes[index] == 0x02 else { return nil }
        let sLen = Int(bytes[index + 1])
        var s = Array(bytes[(index + 2)..<(index + 2 + sLen)])

        r = Array(repeating: 0, count: max(0, 32 - r.count)) + r
        s = Array(repeating: 0, count: max(0, 32 - s.count)) + s

        return r + s
    }

    
    func getSecureEnclavePrivateKey() -> SecKey? {
        let tag = "com.ventus.securekey".data(using: .utf8)!
        
        // If the key already exists, fetch it
        let query: [String: Any] = [
            kSecClass as String:              kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String:        kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String:          true
        ]
        
        var item: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess {
            return (item as! SecKey)
        }
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String:            kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String:      256,
            kSecAttrTokenID as String:            kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag
            ]
        ]
        
        var error: Unmanaged<CFError>?
        let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error)
        return privateKey
        
        }
}
struct CameraPicker: UIViewControllerRepresentable {
    var onImagePicked: (UIImage) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onImagePicked: onImagePicked)
    }

    func makeUIViewController(context: Context) -> UIImagePickerController {
        let picker = UIImagePickerController()
        picker.sourceType = .camera
        picker.allowsEditing = false
        picker.delegate = context.coordinator
        return picker
    }

    func updateUIViewController(_ uiViewController: UIImagePickerController, context: Context) {}

    class Coordinator: NSObject, UINavigationControllerDelegate, UIImagePickerControllerDelegate {
        let onImagePicked: (UIImage) -> Void

        init(onImagePicked: @escaping (UIImage) -> Void) {
            self.onImagePicked = onImagePicked
        }

        func imagePickerController(_ picker: UIImagePickerController, didFinishPickingMediaWithInfo info: [UIImagePickerController.InfoKey : Any]) {
            picker.dismiss(animated: true)
            if let image = info[.editedImage] as? UIImage {
                onImagePicked(image)
            } else if let image = info[.originalImage] as? UIImage {
                onImagePicked(image)
            }
        }

        func imagePickerControllerDidCancel(_ picker: UIImagePickerController) {
            picker.dismiss(animated: true)
        }
    }
}

/*
func runZKProof(
    //pubKeyX: [UInt8],
    //pubKeyY: [UInt8],
    //signature: [UInt8],
    //hash : [UInt8],
    x : String,
    y : String
) throws -> Bool {
    let swoir = Swoir(backend: Swoirenberg.self)

    let files = try! FileManager.default.contentsOfDirectory(atPath: Bundle.main.bundlePath)
    print("All Bundle Files:")
    files.forEach { print("🔹 \($0)") }

    print("App Bundle Path: \(Bundle.main.bundlePath)")
    if let resourcePaths = try? FileManager.default.contentsOfDirectory(atPath: Bundle.main.bundlePath) {
        print("Bundle Contents: \(resourcePaths)")
    }
    
    let manifest = URL(fileURLWithPath: Bundle.main.bundlePath).appendingPathComponent("noircircuits.json")
    print("📦 Using manifest path: \(manifest)")

    //let manifest = URL(fileURLWithPath: Bundle.main.bundlePath).appendingPathComponent("noircircuits.json")
    
    let circuit = try swoir.createCircuit(manifest: manifest)
    try circuit.setupSrs()

    //let inputMap: [String: Any] = [
      //      "pub_key_x": pubKeyX,
        //    "pub_key_y": pubKeyY,
          //  "signature": signature,
            //"data_hash": hash
       // ]
    
    let proof = try circuit.prove(["x" : 1, "y" : 2])
    return try circuit.verify(proof)
}

 */

func runZKProof() throws -> Bool {
    let circuitPath = Bundle.main.path(forResource: "noircircuits", ofType: "json")!
    //let srsPath = Bundle.main.path(forResource: "srs", ofType: "local")!
    //let inputs: [String: String] = ["x": "5", "y": "7"]
    let inputs = "{\"x\":\"5\",\"y\":\"7\"}"


    do {
        let proof = try generateNoirProof(
            circuitPath: circuitPath,
            srsPath: nil,
            inputs: [inputs]
        )
        print("Generated proof:", proof)
        return true
    } catch {
        print("Proof failed:", error)
        return false
    }

}


