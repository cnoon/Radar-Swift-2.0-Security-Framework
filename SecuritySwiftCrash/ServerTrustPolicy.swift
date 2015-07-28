
import Foundation

public class ServerTrustPolicyManager {
    let policies: [String: ServerTrustPolicy]

    public init(policies: [String: ServerTrustPolicy]) {
        self.policies = policies
    }

    func serverTrustPolicyForHost(host: String) -> ServerTrustPolicy? {
        return policies[host]
    }
}

// MARK: -

extension NSURLSession {
    private struct AssociatedKeys {
        static var ManagerKey = "NSURLSession.ServerTrustPolicyManager"
    }

    var serverTrustPolicyManager: ServerTrustPolicyManager? {
        get {
            return objc_getAssociatedObject(self, &AssociatedKeys.ManagerKey) as? ServerTrustPolicyManager
        }
        set (manager) {
            objc_setAssociatedObject(self, &AssociatedKeys.ManagerKey, manager, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
        }
    }
}

// MARK: - ServerTrustPolicy

public enum ServerTrustPolicy {
    case PerformDefaultEvaluation(validateHost: Bool)
    case PinCertificates(certificates: [SecCertificateRef], validateCertificateChain: Bool, validateHost: Bool)
    case PinPublicKeys(publicKeys: [SecKeyRef], validateCertificateChain: Bool, validateHost: Bool)
    case DisableEvaluation
    case CustomEvaluation((serverTrust: SecTrust, host: String) -> Bool)

    // MARK: - Bundle Location

    public static func certificatesInBundle(bundle: NSBundle = NSBundle.mainBundle()) -> [SecCertificate] {
        var certificates: [SecCertificate] = []

        for path in bundle.pathsForResourcesOfType(".cer", inDirectory: nil) {
            if let
                certificateData = NSData(contentsOfFile: path),
                certificate = SecCertificateCreateWithData(nil, certificateData)
            {
                certificates.append(certificate)
            }
        }

        return certificates
    }

    public static func publicKeysInBundle(bundle: NSBundle = NSBundle.mainBundle()) -> [SecKey] {
        var publicKeys: [SecKey] = []

        for certificate in certificatesInBundle(bundle) {
            if let publicKey = publicKeyForCertificate(certificate) {
                publicKeys.append(publicKey)
            }
        }

        return publicKeys
    }

    // MARK: - Evaluation

    public func evaluateServerTrust(serverTrust: SecTrust, isValidForHost host: String) -> Bool {
        var serverTrustIsValid = false

        switch self {
        case let .PerformDefaultEvaluation(validateHost):
            let policy = validateHost ? SecPolicyCreateSSL(1, host as CFString) : SecPolicyCreateBasicX509()
            SecTrustSetPolicies(serverTrust, [policy])

            serverTrustIsValid = trustIsValid(serverTrust)
        case let .PinCertificates(pinnedCertificates, validateCertificateChain, validateHost):
            if validateCertificateChain {
                let policy = validateHost ? SecPolicyCreateSSL(1, host as CFString) : SecPolicyCreateBasicX509()
                SecTrustSetPolicies(serverTrust, [policy])

                SecTrustSetAnchorCertificates(serverTrust, pinnedCertificates)
                SecTrustSetAnchorCertificatesOnly(serverTrust, 1)

                serverTrustIsValid = trustIsValid(serverTrust)
            } else {
                let serverCertificatesDataArray = certificateDataForTrust(serverTrust)
                let pinnedCertificatesDataArray = certificateDataForCertificates(pinnedCertificates) // OFFENDING LINE!!!
//                let pinnedCertificatesDataArray = certificateDataForCertificates([] + pinnedCertificates) // TEMPORARY WORKAROUND

                outerLoop: for serverCertificateData in serverCertificatesDataArray {
                    for pinnedCertificateData in pinnedCertificatesDataArray {
                        if serverCertificateData.isEqualToData(pinnedCertificateData) {
                            serverTrustIsValid = true
                            break outerLoop
                        }
                    }
                }
            }
        case let .PinPublicKeys(pinnedPublicKeys, validateCertificateChain, validateHost):
            var certificateChainEvaluationPassed = true

            if validateCertificateChain {
                let policy = validateHost ? SecPolicyCreateSSL(1, host as CFString) : SecPolicyCreateBasicX509()
                SecTrustSetPolicies(serverTrust, [policy])

                certificateChainEvaluationPassed = trustIsValid(serverTrust)
            }

            if certificateChainEvaluationPassed {
                outerLoop: for serverPublicKey in ServerTrustPolicy.publicKeysForTrust(serverTrust) as [AnyObject] {
                    for pinnedPublicKey in pinnedPublicKeys as [AnyObject] {
                        if serverPublicKey.isEqual(pinnedPublicKey) {
                            serverTrustIsValid = true
                            break outerLoop
                        }
                    }
                }
            }
        case .DisableEvaluation:
            serverTrustIsValid = true
        case let .CustomEvaluation(closure):
            serverTrustIsValid = closure(serverTrust: serverTrust, host: host)
        }

        return serverTrustIsValid
    }

    // MARK: - Private - Trust Validation

    private func trustIsValid(trust: SecTrust) -> Bool {
        var isValid = false

        var result = SecTrustResultType(kSecTrustResultInvalid)
        let status = SecTrustEvaluate(trust, &result)

        if status == errSecSuccess {
            let unspecified = SecTrustResultType(kSecTrustResultUnspecified)
            let proceed = SecTrustResultType(kSecTrustResultProceed)

            isValid = result == unspecified || result == proceed
        }

        return isValid
    }

    // MARK: - Private - Certificate Data

    private func certificateDataForTrust(trust: SecTrustRef) -> [NSData] {
        var certificates: [SecCertificate] = []

        for index in 0..<SecTrustGetCertificateCount(trust) {
            if let certificate = SecTrustGetCertificateAtIndex(trust, index) {
                certificates.append(certificate)
            }
        }

        return certificateDataForCertificates(certificates)
    }

    private func certificateDataForCertificates(certificates: [SecCertificateRef]) -> [NSData] {
        return certificates.map { SecCertificateCopyData($0) as NSData }
    }

    // MARK: - Private - Public Key Extraction

    private static func publicKeysForTrust(trust: SecTrust) -> [SecKey] {
        var publicKeys: [SecKey] = []

        for index in 0..<SecTrustGetCertificateCount(trust) {
            if let
                certificate = SecTrustGetCertificateAtIndex(trust, index),
                publicKey = publicKeyForCertificate(certificate)
            {
                publicKeys.append(publicKey)
            }
        }

        return publicKeys
    }

    private static func publicKeyForCertificate(certificate: SecCertificate) -> SecKey? {
        var publicKey: SecKey?

        let policy = SecPolicyCreateBasicX509()
        var trust: SecTrust?
        let trustCreationStatus = SecTrustCreateWithCertificates(certificate, policy, &trust)

        if let trust = trust where trustCreationStatus == errSecSuccess {
            publicKey = SecTrustCopyPublicKey(trust)
        }

        return publicKey
    }
}
