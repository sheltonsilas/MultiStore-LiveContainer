//
//  Keychain.swift
//  AltStore
//
//  Created by Riley Testut on 6/4/19.
//  Copyright © 2019 Riley Testut. All rights reserved.
//

import Foundation
private import KeychainAccess
import SideSign

@propertyWrapper
public struct KeychainItem<Value>
{
    public let key: String
    
    public var wrappedValue: Value? {
        get {
            switch Value.self
            {
            case is Data.Type: return try? Keychain.shared.keychain.getData(self.key) as? Value
            case is String.Type: return try? Keychain.shared.keychain.getString(self.key) as? Value
            default: return nil
            }
        }
        set {
            switch Value.self
            {
            case is Data.Type: Keychain.shared.keychain[data: self.key] = newValue as? Data
            case is String.Type: Keychain.shared.keychain[self.key] = newValue as? String
            default: break
            }
        }
    }
    
    public init(key: String)
    {
        self.key = key
    }
}

public class Keychain
{
    public static let shared = Keychain()
    
    fileprivate let keychain = KeychainAccess.Keychain(service: Bundle.Info.appbundleIdentifier)
                                            .accessibility(.afterFirstUnlock)
                                            .synchronizable(true)
    
    @KeychainItem(key: "appleIDEmailAddress")
    public var appleIDEmailAddress: String?
    
    @KeychainItem(key: "appleIDPassword")
    public var appleIDPassword: String?
    
    @KeychainItem(key: "appleIDAdsid")
    public var appleIDAdsid: String?
    
    @KeychainItem(key: "appleIDXcodeToken")
    public var appleIDXcodeToken: String?
    
    @KeychainItem(key: "signingCertificate")
    public var signingCertificate: Data?
    
    @KeychainItem(key: "signingCertificatePassword")
    public var signingCertificatePassword: String?
    
    // TODO: mahee96: remove legacy keys in later versions after 0.6.4 coz by now our migrations should be effectively moved all
    // Legacy
    @KeychainItem(key: "signingCertificatePrivateKey")
    public var signingCertificatePrivateKey: Data?
    
    // TODO: mahee96: remove legacy keys in later versions after 0.6.4 coz by now our migrations should be effectively moved all
    // Legacy
    @KeychainItem(key: "signingCertificateSerialNumber")
    public var signingCertificateSerialNumber: String?
    
    @KeychainItem(key: "identifier")
    public var identifier: String?
    
    @KeychainItem(key: "adiPb")
    public var adiPb: String?

    @KeychainItem(key: "deviceUDID")
    public var deviceUDID: String?

    // MARK: - Dynamic Imported Certificates Storage

    public subscript(certificateSerial serial: String) -> Data? {
        get { try? self.keychain.getData("importedCert_" + serial) }
        set {
            if let data = newValue {
                try? self.keychain.set(data, key: "importedCert_" + serial)
            } else {
                try? self.keychain.remove("importedCert_" + serial)
            }
        }
    }
    
    private init()
    {
        self.migrateLegacyKeychainItems()
    }
    
    private func migrateLegacyKeychainItems()
    {
        let signingCertificateKey   = "signingCertificate"
        let privateKeyKey           = "signingCertificatePrivateKey"
        let serialNumberKey         = "signingCertificateSerialNumber"
        
        // 1. Check if signingCertificate contains data and is NOT a PKCS#12 archive
        guard let certData = try? self.keychain.getData(signingCertificateKey), !certData.isPKCS12 else { return }
        
        // 2. Check if we have the private key
        guard let privateKey = try? self.keychain.getData(privateKeyKey) else { return }
        
        // 3. Load the raw certificate and pair with private key
        guard let x509 = ALTX509Certificate(data: certData) else { return }
        let cert = ALTCertificate(x509: x509, privateKey: privateKey)
        
        // 4. Create PKCS12 data structure
        do {
            let p12Data = try cert.unencryptedP12Data()
            // 5. Store the new PKCS12 format in signingCertificate slot
            try self.keychain.set(p12Data, key: signingCertificateKey)
            try self.keychain.set("", key: "signingCertificatePassword")
            
            // 6. Clear legacy keys
            try self.keychain.remove(privateKeyKey)
            try self.keychain.remove(serialNumberKey)
            
            debugLog("[Keychain] Successfully migrated legacy certificate and private key to PKCS12 format and cleared legacy keys.")
        } catch {
            debugLog("[Keychain] Failed to migrate legacy certificate to PKCS12 format: \(error)")
        }
    }
    
    public func clearCertificates()
    {
        // Legacy
        self.signingCertificatePrivateKey = nil
        self.signingCertificateSerialNumber = nil

        self.signingCertificate = nil
        self.signingCertificatePassword = nil
        
        debugLog("[Keychain] Cleared signing certificate & private key from Keychain.")
    }
    
    public func clearSignInInfo(keepAnisetteData: Bool = true)
    {
        debugLog("[Keychain] Clearing sign-in info from Keychain (keepAnisetteData: \(keepAnisetteData))...")
        
        self.appleIDEmailAddress = nil
        self.appleIDPassword = nil
        self.appleIDAdsid = nil
        self.appleIDXcodeToken = nil
        debugLog("[Keychain] Cleared Apple ID credentials & tokens (email, password, adsid, xcodeToken).")

        if !keepAnisetteData {
            self.adiPb = nil
            debugLog("[Keychain] Cleared Anisette ADI data (adiPb).")
        } else {
            debugLog("[Keychain] Preserved Anisette ADI data (adiPb).")
        }
        
        debugLog("[Keychain] Cleared sign-in info from Keychain.")
    }

    public func clearAll()
    {
        debugLog("[Keychain] Clearing all Keychain items related to this instance...")
        try? self.keychain.removeAll()
        debugLog("[Keychain] All Keychain items cleared.")
    }
}

// MARK: - Multi-Account Credentials

public extension Keychain
{
    /// The set of keychain items that belong to a single Apple ID.
    ///
    /// Multi-account support keeps each account's session and signing identity in its
    /// own keychain namespace, keyed by `Account.identifier` (which already has a
    /// uniqueness constraint in Core Data). The legacy un-namespaced properties remain
    /// the storage for the account that was signed in before this feature existed;
    /// `migrateLegacyCredentials(to:)` copies them into that account's namespace once.
    struct AccountCredentials
    {
        public var emailAddress: String?
        public var password: String?
        public var adsid: String?
        public var xcodeToken: String?
        public var signingCertificate: Data?
        public var signingCertificatePassword: String?

        public var isEmpty: Bool {
            return self.emailAddress == nil && self.password == nil && self.adsid == nil &&
                   self.xcodeToken == nil && self.signingCertificate == nil &&
                   self.signingCertificatePassword == nil
        }
    }

    /// Namespaces an account-scoped key, mirroring the existing `importedCert_<serial>` scheme.
    private func accountScopedKey(_ accountIdentifier: String, _ suffix: String) -> String {
        return "acct." + accountIdentifier + "." + suffix
    }

    subscript(credentialsFor accountIdentifier: String) -> AccountCredentials
    {
        get {
            return AccountCredentials(
                emailAddress: try? self.keychain.getString(self.accountScopedKey(accountIdentifier, "appleIDEmailAddress")),
                password: try? self.keychain.getString(self.accountScopedKey(accountIdentifier, "appleIDPassword")),
                adsid: try? self.keychain.getString(self.accountScopedKey(accountIdentifier, "appleIDAdsid")),
                xcodeToken: try? self.keychain.getString(self.accountScopedKey(accountIdentifier, "appleIDXcodeToken")),
                signingCertificate: try? self.keychain.getData(self.accountScopedKey(accountIdentifier, "signingCertificate")),
                signingCertificatePassword: try? self.keychain.getString(self.accountScopedKey(accountIdentifier, "signingCertificatePassword"))
            )
        }
        set {
            let setString: (String, String?) -> Void = { key, value in
                if let value = value { try? self.keychain.set(value, key: key) }
                else { try? self.keychain.remove(key) }
            }
            let setData: (String, Data?) -> Void = { key, value in
                if let value = value { try? self.keychain.set(value, key: key) }
                else { try? self.keychain.remove(key) }
            }

            setString(self.accountScopedKey(accountIdentifier, "appleIDEmailAddress"), newValue.emailAddress)
            setString(self.accountScopedKey(accountIdentifier, "appleIDPassword"), newValue.password)
            setString(self.accountScopedKey(accountIdentifier, "appleIDAdsid"), newValue.adsid)
            setString(self.accountScopedKey(accountIdentifier, "appleIDXcodeToken"), newValue.xcodeToken)
            setData(self.accountScopedKey(accountIdentifier, "signingCertificate"), newValue.signingCertificate)
            setString(self.accountScopedKey(accountIdentifier, "signingCertificatePassword"), newValue.signingCertificatePassword)
        }
    }

    /// Removes every credential stored for `accountIdentifier`.
    func clearCredentials(for accountIdentifier: String) {
        self[credentialsFor: accountIdentifier] = AccountCredentials()
        debugLog("[Keychain] Cleared credentials for account namespace.")
    }

    /// Copies the legacy single-account keychain items into `accountIdentifier`'s namespace.
    ///
    /// Upgrading users have their session and certificate in the un-namespaced keys.
    /// This claims them for the currently active account exactly once; an account that
    /// already has namespaced credentials is left untouched, so it is safe to call repeatedly.
    func migrateLegacyCredentials(to accountIdentifier: String) {
        guard !accountIdentifier.isEmpty else { return }
        guard self[credentialsFor: accountIdentifier].isEmpty else { return }

        var migrated = AccountCredentials()
        migrated.emailAddress = self.appleIDEmailAddress
        migrated.password = self.appleIDPassword
        migrated.adsid = self.appleIDAdsid
        migrated.xcodeToken = self.appleIDXcodeToken
        migrated.signingCertificate = self.signingCertificate
        migrated.signingCertificatePassword = self.signingCertificatePassword

        guard !migrated.isEmpty else { return }

        self[credentialsFor: accountIdentifier] = migrated
        debugLog("[Keychain] Migrated legacy single-account credentials into the account namespace.")
    }
}
