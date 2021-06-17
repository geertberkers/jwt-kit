import LoggerAPI
import Foundation

/// The "exp" (expiration time) claim identifies the expiration time on
/// or after which the JWT MUST NOT be accepted for processing.  The
/// processing of the "exp" claim requires that the current date/time
/// MUST be before the expiration date/time listed in the "exp" claim.
/// Implementers MAY provide for some small leeway, usually no more than
/// a few minutes, to account for clock skew.  Its value MUST be a number
/// containing a NumericDate value.  Use of this claim is OPTIONAL.
public struct ExpirationClaim: JWTUnixEpochClaim, Equatable {
    
    public var ISO8601DateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat =  "yyyy-MM-dd'T'HH:mm:ss.SSSSZZZ"
        formatter.timeZone = TimeZone(abbreviation: "GMT+02")
        return formatter
    }()
    
    /// See `JWTClaim`.
    public var value: Date

    /// See `JWTClaim`.
    public init(value: Date) {
        self.value = value
    }

    /// Throws an error if the claim's date is later than current date.
    public func verifyNotExpired(currentDate: Date = .init()) throws {
        let initDateString = ISO8601DateFormatter.string(from: self.value)
        let currentDateString = ISO8601DateFormatter.string(from: currentDate)

        Log.debug("Date:         \(initDateString)")
        Log.debug("Current Date: \(currentDateString)")
        
        switch self.value.compare(currentDate) {
        case .orderedAscending:
            Log.debug("Value ascending!")
            throw JWTError.claimVerificationFailure(name: "exp", reason: "expired")
        case .orderedSame:
            Log.debug("Value ordered same!")
            throw JWTError.claimVerificationFailure(name: "exp", reason: "expired")
        case .orderedDescending:
            Log.debug("Value descending!")
            break
        }
    }
}
