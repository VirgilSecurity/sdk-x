//
// Copyright (C) 2015-2019 Virgil Security Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//

import Foundation

/// Timer class
public class Timer {
    private let timer: DispatchSourceTimer

    private enum State {
        case suspended
        case resumed
    }

    private var state: State = .suspended

    // swiftlint:disable missing_docs

    /// Timer type
    public enum TimerType {
        case oneTime(TimeInterval)
        case repeating(Bool, TimeInterval)
    }

    // swiftlint:enable missing_docs

    /// Init
    /// - Parameters:
    ///   - interval: TimeInterval
    ///   - repeating: will repeat if true
    ///   - startFromNow: start now
    ///   - handler: timer handler
    public init(timerType: TimerType,
                handler: @escaping () -> Void) {

        let timer = DispatchSource.makeTimerSource()

        switch timerType {
        case .oneTime(let interval):
            timer.schedule(deadline: .now() + interval)

        case let .repeating(startFromNow, interval):
            let startAfter = startFromNow ? 0 : interval

            timer.schedule(deadline: .now() + startAfter, repeating: interval)
        }

        timer.setEventHandler(handler: handler)

        self.timer = timer
    }

    deinit {
        self.timer.setEventHandler {}
        self.timer.cancel()

        /*
         If the timer is suspended, calling cancel without resuming
         triggers a crash. This is documented here https://forums.developer.apple.com/thread/15902
         */

        self.resume()
    }

    /// Resumes timer
    public func resume() {
        if self.state == .resumed {
            return
        }

        self.state = .resumed
        self.timer.resume()
    }

    /// Suspends timer
    public func suspend() {
        if self.state == .suspended {
            return
        }

        self.state = .suspended
        self.timer.suspend()
    }
}
