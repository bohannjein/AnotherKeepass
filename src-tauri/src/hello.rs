//! Windows Hello (face, fingerprint or PIN) as the gate for quick unlock.
//! Blocking calls: run them off the main thread.

#[cfg(windows)]
mod imp {
    use windows::{
        core::{factory, HSTRING},
        Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability},
        Win32::{Foundation::HWND, System::WinRT::IUserConsentVerifierInterop},
    };
    use windows_future::IAsyncOperation;

    pub fn available() -> bool {
        UserConsentVerifier::CheckAvailabilityAsync()
            .and_then(|op| op.get())
            .is_ok_and(|a| a == UserConsentVerifierAvailability::Available)
    }

    /// Shows the Hello prompt on top of our window; true = verified.
    pub fn verify(hwnd: isize, message: &str) -> bool {
        let res = (|| -> windows::core::Result<UserConsentVerificationResult> {
            let interop = factory::<UserConsentVerifier, IUserConsentVerifierInterop>()?;
            let op: IAsyncOperation<UserConsentVerificationResult> =
                unsafe { interop.RequestVerificationForWindowAsync(HWND(hwnd as *mut _), &HSTRING::from(message))? };
            op.get()
        })();
        match res {
            Ok(r) => r == UserConsentVerificationResult::Verified,
            Err(e) => {
                log::warn!("windows hello: {e}");
                false
            }
        }
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn available() -> bool {
        false
    }
    pub fn verify(_hwnd: isize, _message: &str) -> bool {
        false
    }
}

pub use imp::{available, verify};
