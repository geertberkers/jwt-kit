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
    
    var ISO8601DateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat =  "yyyy-MM-dd'T'HH:mm:ss.SSSSZZZ"
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        return formatter
    }()
    
    let addHours: Double  = 60 * 60 * 2 // (60 seconds * 60 minutes * 2 hours)
        
//    var addHours: Double {
//        60 * 60 * 2 // (60 seconds * 60 minutes * 2 hours)
//    }
    
    /// See `JWTClaim`.
    public var value: Date

    /// See `JWTClaim`.
    public init(value: Date) {
        self.value = value

        let addedTime = value.addingTimeInterval(self.addHours)
        let initDateString = ISO8601DateFormatter.string(from: value)
        let addedDateString = ISO8601DateFormatter.string(from: addedTime)

        Log.debug("Self date: \(selfDateString))")
        Log.debug("Date + 2H: \(addedDateString)")
    }

    /// Throws an error if the claim's date is later than current date.
    public func verifyNotExpired(currentDate: Date = .init()) throws {
        let initDateString = ISO8601DateFormatter.string(from: value)
        let currentDateString = ISO8601DateFormatter.string(from: currentDate)

        Log.debug("Self date: \(initDateString))")
        Log.debug("Current Date: \(currentDateString)")
//        let updatedCurrentDate = currentDate.addingTimeInterval(-addHours)
//
//        let currentDateString = ISO8601DateFormatter.string(from: currentDate)
//        let updatedDateString = ISO8601DateFormatter.string(from: updatedCurrentDate)
//
//        Log.debug("Current date: \(currentDateString)")
//        Log.debug("Updated date (-2H): \(updatedDateString)")

        switch self.value.compare(currentDate) {
        case .orderedAscending, .orderedSame:
            throw JWTError.claimVerificationFailure(name: "exp", reason: "expired")
        case .orderedDescending:
            break
        }
    }
}
