//
//  MultiAccountManager.swift
//  SideStore
//
//  Created for MultiStore.
//  Copyright © 2026 MultiStore. All rights reserved.
//

import Foundation
import CoreData
import SideSign

/// Owns everything multi-account that the rest of the app should not need to know about:
/// which Apple ID signs which app, and temporarily making one account the account that
/// signing operations use.
///
/// Why switching instead of threading an account through every operation: SideStore resolves
/// its session, team and signing certificate from a single shared slot — `Keychain.shared.appleID*`,
/// the `isActiveAccount`/`isActiveTeam` Core Data flags, and `CertificateManager.activeCertificate`.
/// Every step of the signing pipeline reads that slot. Rather than refactor all of them,
/// MultiStore keeps the account list authoritative, publishes the account that is about to sign
/// into the shared slot, and hands the user's chosen account back afterwards.
///
/// Each account owns a keychain namespace (`Keychain[credentialsFor:]`), so switching never
/// destroys another account's session or certificate.
public final class MultiAccountManager
{
    public static let shared = MultiAccountManager()

    private init() {}

    // MARK: - Account list

    /// The identifier of the account whose credentials currently occupy the shared keychain slots.
    public func activeAccountIdentifier(in context: NSManagedObjectContext) async -> String?
    {
        return await context.perform {
            DatabaseManager.shared.activeAccount(in: context)?.identifier
        }
    }

    // MARK: - Switching

    /// Makes `accountIdentifier` the account that signing operations use.
    ///
    /// Publishes that account's session and certificate into the shared slots and clears
    /// `AuthManager`'s cached session/team so the next pipeline step re-resolves them.
    /// Returns `false` when the account no longer exists.
    @discardableResult
    public func activateAccount(withIdentifier accountIdentifier: String,
                               in context: NSManagedObjectContext) async throws -> Bool
    {
        // File whatever the shared slots currently hold under the outgoing account first, so
        // switching can never lose the account we are leaving.
        await self.captureActiveAccountCredentials(in: context)

        let activatedIdentifier: String? = try await context.perform {
            guard let account = DatabaseManager.shared.account(withIdentifier: accountIdentifier, in: context) else {
                return nil
            }

            account.isActiveAccount = true
            for other in DatabaseManager.shared.allAccounts(in: context) where other.identifier != account.identifier {
                other.isActiveAccount = false
            }

            if let team = DatabaseManager.shared.signingTeam(for: account, in: context) {
                team.isActiveTeam = true
                let teams = (try? context.fetch(Team.fetchRequest() as NSFetchRequest<Team>)) ?? []
                for other in teams where other.identifier != team.identifier {
                    other.isActiveTeam = false
                }
            }

            try context.save()
            return account.identifier
        }

        guard let identifier = activatedIdentifier else {
            debugLog("[MultiAccountManager] activateAccount: no account matches the requested identifier.")
            return false
        }

        try self.publishCredentials(for: identifier)
        AuthManager.shared.invalidateCachedSession()

        // The view context is a separate object graph, so make it observe the new active flags.
        await MainActor.run {
            DatabaseManager.shared.viewContext.processPendingChanges()
        }

        debugLog("[MultiAccountManager] Activated account for signing.")
        return true
    }

    // MARK: - Credential namespacing

    /// Copies the shared keychain slots into the active account's own namespace.
    public func captureActiveAccountCredentials(in context: NSManagedObjectContext) async
    {
        guard let identifier = await self.activeAccountIdentifier(in: context) else { return }
        self.captureSharedCredentials(for: identifier)
    }

    /// Context-free variant for callers that only have the database singleton (e.g. sign-in).
    public func captureActiveAccountCredentials() async
    {
        let context = DatabaseManager.shared.persistentContainer.newBackgroundContext()
        await self.captureActiveAccountCredentials(in: context)
    }

    /// Files the credentials a completed sign-in produced under the new account's namespace,
    /// so signing into an additional account never costs us the one that was already here.
    ///
    /// Not `public`: `SignInResult` is module-internal.
    func registerCredentials(for result: SignInResult)
    {
        let identifier = result.team.account?.identifier ?? result.team.identifier
        guard !identifier.isEmpty else { return }

        self.captureSharedCredentials(for: identifier)

        // The Apple ID we just signed into is authoritative for the e-mail field.
        var credentials = Keychain.shared[credentialsFor: identifier]
        if credentials.emailAddress == nil, let appleID = result.team.account?.appleID {
            credentials.emailAddress = appleID
            Keychain.shared[credentialsFor: identifier] = credentials
        }

        debugLog("[MultiAccountManager] Registered credentials for a newly signed-in account.")
    }

    /// Forgets every credential belonging to `accountIdentifier`. Used when an account is removed.
    public func forgetCredentials(for accountIdentifier: String)
    {
        Keychain.shared.clearCredentials(for: accountIdentifier)
    }

    // MARK: - Shared slot

    private func captureSharedCredentials(for accountIdentifier: String)
    {
        // Claims any pre-multi-account credentials for this account the first time we touch it.
        Keychain.shared.migrateLegacyCredentials(to: accountIdentifier)

        var credentials = Keychain.shared[credentialsFor: accountIdentifier]

        // Only overwrite fields the shared slot actually has. A signed-out or partially
        // populated shared slot cannot blank credentials this account already stored.
        if let emailAddress = Keychain.shared.appleIDEmailAddress { credentials.emailAddress = emailAddress }
        if let password = Keychain.shared.appleIDPassword { credentials.password = password }
        if let adsid = Keychain.shared.appleIDAdsid { credentials.adsid = adsid }
        if let xcodeToken = Keychain.shared.appleIDXcodeToken { credentials.xcodeToken = xcodeToken }
        if let certificate = Keychain.shared.signingCertificate {
            credentials.signingCertificate = certificate
            credentials.signingCertificatePassword = Keychain.shared.signingCertificatePassword
        }

        Keychain.shared[credentialsFor: accountIdentifier] = credentials
        debugLog("[MultiAccountManager] Captured the shared keychain state for the active account.")
    }

    /// Publishes `accountIdentifier`'s stored credentials into the shared keychain slots so the
    /// existing single-account signing pipeline uses them without modification.
    private func publishCredentials(for accountIdentifier: String) throws
    {
        let credentials = Keychain.shared[credentialsFor: accountIdentifier]

        // Assign the whole set: leaving a field behind would let one account sign with another's identity.
        Keychain.shared.appleIDEmailAddress = credentials.emailAddress
        Keychain.shared.appleIDPassword = credentials.password
        Keychain.shared.appleIDAdsid = credentials.adsid
        Keychain.shared.appleIDXcodeToken = credentials.xcodeToken

        if let certificateData = credentials.signingCertificate {
            Keychain.shared.signingCertificate = certificateData
            Keychain.shared.signingCertificatePassword = credentials.signingCertificatePassword
            try CertificateManager.shared.loadActiveCertificate()
        } else {
            // This account has no signing identity yet; the certificate provisioning flow will
            // mint one for it. Clearing stops us signing with the account we switched away from.
            CertificateManager.shared.clearActiveCertificate()
        }

        debugLog("[MultiAccountManager] Published the activated account's credentials.")
    }
}
