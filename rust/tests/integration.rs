/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Rust Binder crate integration tests

use binder::declare_binder_interface;
use binder::parcel::Parcel;
use binder::{
    Binder, IBinderInternal, Interface, StatusCode, ThreadState, TransactionCode,
    FIRST_CALL_TRANSACTION,
};
use std::convert::{TryFrom, TryInto};

/// Name of service runner.
///
/// Must match the binary name in Android.bp
const RUST_SERVICE_BINARY: &str = "rustBinderTestService";

/// Binary to run a test service.
///
/// This needs to be in a separate process from the tests, so we spawn this
/// binary as a child, providing the service name as an argument.
fn main() -> Result<(), &'static str> {
    // Ensure that we can handle all transactions on the main thread.
    binder::ProcessState::set_thread_pool_max_thread_count(0);
    binder::ProcessState::start_thread_pool();

    let mut args = std::env::args().skip(1);
    if args.len() < 1 || args.len() > 2 {
        print_usage();
        return Err("");
    }
    let service_name = args.next().ok_or_else(|| {
        print_usage();
        "Missing SERVICE_NAME argument"
    })?;
    let extension_name = args.next();

    {
        let mut service = Binder::new(BnTest(Box::new(TestService {
            s: service_name.clone(),
        })));
        service.set_requesting_sid(true);
        if let Some(extension_name) = extension_name {
            let extension = BnTest::new_binder(TestService { s: extension_name });
            service
                .set_extension(&mut extension.as_binder())
                .expect("Could not add extension");
        }
        binder::add_service(&service_name, service.as_binder())
            .expect("Could not register service");
    }

    binder::ProcessState::join_thread_pool();
    Err("Unexpected exit after join_thread_pool")
}

fn print_usage() {
    eprintln!(
        "Usage: {} SERVICE_NAME [EXTENSION_NAME]",
        RUST_SERVICE_BINARY
    );
    eprintln!(concat!(
        "Spawn a Binder test service identified by SERVICE_NAME,",
        " optionally with an extesion named EXTENSION_NAME",
    ));
}

#[derive(Clone)]
struct TestService {
    s: String,
}

#[repr(u32)]
enum TestTransactionCode {
    Test = FIRST_CALL_TRANSACTION,
    GetSelinuxContext,
}

impl TryFrom<u32> for TestTransactionCode {
    type Error = StatusCode;

    fn try_from(c: u32) -> Result<Self, Self::Error> {
        match c {
            _ if c == TestTransactionCode::Test as u32 => Ok(TestTransactionCode::Test),
            _ if c == TestTransactionCode::GetSelinuxContext as u32 => {
                Ok(TestTransactionCode::GetSelinuxContext)
            }
            _ => Err(StatusCode::UNKNOWN_TRANSACTION),
        }
    }
}

impl Interface for TestService {}

impl ITest for TestService {
    fn test(&self) -> binder::Result<String> {
        Ok(self.s.clone())
    }

    fn get_selinux_context(&self) -> binder::Result<String> {
        let sid =
            ThreadState::with_calling_sid(|sid| sid.map(|s| s.to_string_lossy().into_owned()));
        sid.ok_or(StatusCode::UNEXPECTED_NULL)
    }
}

/// Trivial testing binder interface
pub trait ITest: Interface {
    /// Returns a test string
    fn test(&self) -> binder::Result<String>;

    /// Returns the caller's SELinux context
    fn get_selinux_context(&self) -> binder::Result<String>;
}

declare_binder_interface! {
    ITest["android.os.ITest"] {
        native: BnTest(on_transact),
        proxy: BpTest {
            x: i32 = 100
        },
    }
}

fn on_transact(
    service: &dyn ITest,
    code: TransactionCode,
    _data: &Parcel,
    reply: &mut Parcel,
) -> binder::Result<()> {
    match code.try_into()? {
        TestTransactionCode::Test => reply.write(&service.test()?),
        TestTransactionCode::GetSelinuxContext => reply.write(&service.get_selinux_context()?),
    }
}

impl ITest for BpTest {
    fn test(&self) -> binder::Result<String> {
        let reply =
            self.binder
                .transact(TestTransactionCode::Test as TransactionCode, 0, |_| Ok(()))?;
        reply.read()
    }

    fn get_selinux_context(&self) -> binder::Result<String> {
        let reply = self.binder.transact(
            TestTransactionCode::GetSelinuxContext as TransactionCode,
            0,
            |_| Ok(()),
        )?;
        reply.read()
    }
}

impl ITest for Binder<BnTest> {
    fn test(&self) -> binder::Result<String> {
        self.0.test()
    }

    fn get_selinux_context(&self) -> binder::Result<String> {
        self.0.get_selinux_context()
    }
}

/// Trivial testing binder interface
pub trait ITestSameDescriptor: Interface {}

declare_binder_interface! {
    ITestSameDescriptor["android.os.ITest"] {
        native: BnTestSameDescriptor(on_transact_same_descriptor),
        proxy: BpTestSameDescriptor,
    }
}

fn on_transact_same_descriptor(
    _service: &dyn ITestSameDescriptor,
    _code: TransactionCode,
    _data: &Parcel,
    _reply: &mut Parcel,
) -> binder::Result<()> {
    Ok(())
}

impl ITestSameDescriptor for BpTestSameDescriptor {}

impl ITestSameDescriptor for Binder<BnTestSameDescriptor> {}

#[cfg(test)]
mod tests {
    use selinux_bindgen as selinux_sys;
    use std::ffi::CStr;
    use std::fs::File;
    use std::process::{Child, Command};
    use std::ptr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use binder::{
        Binder, DeathRecipient, FromIBinder, IBinder, IBinderInternal, Interface, SpIBinder,
        StatusCode, Strong,
    };

    use super::{BnTest, ITest, ITestSameDescriptor, TestService, RUST_SERVICE_BINARY};

    pub struct ScopedServiceProcess(Child);

    impl ScopedServiceProcess {
        pub fn new(identifier: &str) -> Self {
            Self::new_internal(identifier, None)
        }

        pub fn new_with_extension(identifier: &str, extension: &str) -> Self {
            Self::new_internal(identifier, Some(extension))
        }

        fn new_internal(identifier: &str, extension: Option<&str>) -> Self {
            let mut binary_path =
                std::env::current_exe().expect("Could not retrieve current executable path");
            binary_path.pop();
            binary_path.push(RUST_SERVICE_BINARY);
            let mut command = Command::new(&binary_path);
            command.arg(identifier);
            if let Some(ext) = extension {
                command.arg(ext);
            }
            let child = command.spawn().expect("Could not start service");
            Self(child)
        }
    }

    impl Drop for ScopedServiceProcess {
        fn drop(&mut self) {
            self.0.kill().expect("Could not kill child process");
            self.0
                .wait()
                .expect("Could not wait for child process to die");
        }
    }

    #[test]
    fn check_services() {
        let mut sm = binder::get_service("manager").expect("Did not get manager binder service");
        assert!(sm.is_binder_alive());
        assert!(sm.ping_binder().is_ok());

        assert!(binder::get_service("this_service_does_not_exist").is_none());
        assert_eq!(
            binder::get_interface::<dyn ITest>("this_service_does_not_exist").err(),
            Some(StatusCode::NAME_NOT_FOUND)
        );

        // The service manager service isn't an ITest, so this must fail.
        assert_eq!(
            binder::get_interface::<dyn ITest>("manager").err(),
            Some(StatusCode::BAD_TYPE)
        );
    }

    #[test]
    fn trivial_client() {
        let service_name = "trivial_client_test";
        let _process = ScopedServiceProcess::new(service_name);
        let test_client: Strong<dyn ITest> =
            binder::get_interface(service_name).expect("Did not get manager binder service");
        assert_eq!(test_client.test().unwrap(), "trivial_client_test");
    }

    #[test]
    fn get_selinux_context() {
        let service_name = "get_selinux_context";
        let _process = ScopedServiceProcess::new(service_name);
        let test_client: Strong<dyn ITest> =
            binder::get_interface(service_name).expect("Did not get manager binder service");
        let expected_context = unsafe {
            let mut out_ptr = ptr::null_mut();
            assert_eq!(selinux_sys::getcon(&mut out_ptr), 0);
            assert!(!out_ptr.is_null());
            CStr::from_ptr(out_ptr)
        };
        assert_eq!(
            test_client.get_selinux_context().unwrap(),
            expected_context
                .to_str()
                .expect("context was invalid UTF-8"),
        );
    }

    fn register_death_notification(binder: &mut SpIBinder) -> (Arc<AtomicBool>, DeathRecipient) {
        let binder_died = Arc::new(AtomicBool::new(false));

        let mut death_recipient = {
            let flag = binder_died.clone();
            DeathRecipient::new(move || {
                flag.store(true, Ordering::Relaxed);
            })
        };

        binder
            .link_to_death(&mut death_recipient)
            .expect("link_to_death failed");

        (binder_died, death_recipient)
    }

    /// Killing a remote service should unregister the service and trigger
    /// death notifications.
    #[test]
    fn test_death_notifications() {
        binder::ProcessState::start_thread_pool();

        let service_name = "test_death_notifications";
        let service_process = ScopedServiceProcess::new(service_name);
        let mut remote = binder::get_service(service_name).expect("Could not retrieve service");

        let (binder_died, _recipient) = register_death_notification(&mut remote);

        drop(service_process);
        remote
            .ping_binder()
            .expect_err("Service should have died already");

        // Pause to ensure any death notifications get delivered
        thread::sleep(Duration::from_secs(1));

        assert!(
            binder_died.load(Ordering::Relaxed),
            "Did not receive death notification"
        );
    }

    /// Test unregistering death notifications.
    #[test]
    fn test_unregister_death_notifications() {
        binder::ProcessState::start_thread_pool();

        let service_name = "test_unregister_death_notifications";
        let service_process = ScopedServiceProcess::new(service_name);
        let mut remote = binder::get_service(service_name).expect("Could not retrieve service");

        let (binder_died, mut recipient) = register_death_notification(&mut remote);

        remote
            .unlink_to_death(&mut recipient)
            .expect("Could not unlink death notifications");

        drop(service_process);
        remote
            .ping_binder()
            .expect_err("Service should have died already");

        // Pause to ensure any death notifications get delivered
        thread::sleep(Duration::from_secs(1));

        assert!(
            !binder_died.load(Ordering::Relaxed),
            "Received unexpected death notification after unlinking",
        );
    }

    /// Dropping a remote handle should unregister any death notifications.
    #[test]
    fn test_death_notification_registration_lifetime() {
        binder::ProcessState::start_thread_pool();

        let service_name = "test_death_notification_registration_lifetime";
        let service_process = ScopedServiceProcess::new(service_name);
        let mut remote = binder::get_service(service_name).expect("Could not retrieve service");

        let (binder_died, _recipient) = register_death_notification(&mut remote);

        // This should automatically unregister our death notification.
        drop(remote);

        drop(service_process);

        // Pause to ensure any death notifications get delivered
        thread::sleep(Duration::from_secs(1));

        // We dropped the remote handle, so we should not receive the death
        // notification when the remote process dies here.
        assert!(
            !binder_died.load(Ordering::Relaxed),
            "Received unexpected death notification after dropping remote handle"
        );
    }

    /// Test IBinder interface methods not exercised elsewhere.
    #[test]
    fn test_misc_ibinder() {
        let service_name = "rust_test_ibinder";

        {
            let _process = ScopedServiceProcess::new(service_name);

            let mut remote = binder::get_service(service_name);
            assert!(remote.is_binder_alive());
            remote.ping_binder().expect("Could not ping remote service");

            // We're not testing the output of dump here, as that's really a
            // property of the C++ implementation. There is the risk that the
            // method just does nothing, but we don't want to depend on any
            // particular output from the underlying library.
            let null_out = File::open("/dev/null").expect("Could not open /dev/null");
            remote
                .dump(&null_out, &[])
                .expect("Could not dump remote service");
        }

        // get/set_extensions is tested in test_extensions()

        // transact is tested everywhere else, and we can't make raw
        // transactions outside the [FIRST_CALL_TRANSACTION,
        // LAST_CALL_TRANSACTION] range from the NDK anyway.

        // link_to_death is tested in test_*_death_notification* tests.
    }

    #[test]
    fn test_extensions() {
        let service_name = "rust_test_extensions";
        let extension_name = "rust_test_extensions_ext";

        {
            let _process = ScopedServiceProcess::new(service_name);

            let mut remote = binder::get_service(service_name);
            assert!(remote.is_binder_alive());

            let extension = remote
                .get_extension()
                .expect("Could not check for an extension");
            assert!(extension.is_none());
        }

        {
            let _process = ScopedServiceProcess::new_with_extension(service_name, extension_name);

            let mut remote = binder::get_service(service_name);
            assert!(remote.is_binder_alive());

            let maybe_extension = remote
                .get_extension()
                .expect("Could not check for an extension");

            let extension = maybe_extension.expect("Remote binder did not have an extension");

            let extension: Strong<dyn ITest> = FromIBinder::try_from(extension)
                .expect("Extension could not be converted to the expected interface");

            assert_eq!(extension.test().unwrap(), extension_name);
        }
    }

    /// Test re-associating a local binder object with a different class.
    ///
    /// This is needed because different binder service (e.g. NDK vs Rust)
    /// implementations are incompatible and must not be interchanged. A local
    /// service with the same descriptor string but a different class pointer
    /// may have been created by an NDK service and is therefore incompatible
    /// with the Rust service implementation. It must be treated as remote and
    /// all API calls parceled and sent through transactions.
    ///
    /// Further tests of this behavior with the C NDK and Rust API are in
    /// rust_ndk_interop.rs
    #[test]
    fn associate_existing_class() {
        let service = Binder::new(BnTest(Box::new(TestService {
            s: "testing_service".to_string(),
        })));

        // This should succeed although we will have to treat the service as
        // remote.
        let _interface: Strong<dyn ITestSameDescriptor> =
            FromIBinder::try_from(service.as_binder())
                .expect("Could not re-interpret service as the ITestSameDescriptor interface");
    }

    /// Test that we can round-trip a rust service through a generic IBinder
    #[test]
    fn reassociate_rust_binder() {
        let service_name = "testing_service";
        let service_ibinder = BnTest::new_binder(TestService {
            s: service_name.to_string(),
        })
        .as_binder();

        let service: Strong<dyn ITest> = service_ibinder
            .into_interface()
            .expect("Could not reassociate the generic ibinder");

        assert_eq!(service.test().unwrap(), service_name);
    }

    #[test]
    fn weak_binder_upgrade() {
        let service_name = "testing_service";
        let service = BnTest::new_binder(TestService {
            s: service_name.to_string(),
        });

        let weak = Strong::downgrade(&service);

        let upgraded = weak.upgrade().expect("Could not upgrade weak binder");

        assert_eq!(service, upgraded);
    }

    #[test]
    fn weak_binder_upgrade_dead() {
        let service_name = "testing_service";
        let weak = {
            let service = BnTest::new_binder(TestService {
                s: service_name.to_string(),
            });

            Strong::downgrade(&service)
        };

        assert_eq!(weak.upgrade(), Err(StatusCode::DEAD_OBJECT));
    }

    #[test]
    fn weak_binder_clone() {
        let service_name = "testing_service";
        let service = BnTest::new_binder(TestService {
            s: service_name.to_string(),
        });

        let weak = Strong::downgrade(&service);
        let cloned = weak.clone();
        assert_eq!(weak, cloned);

        let upgraded = weak.upgrade().expect("Could not upgrade weak binder");
        let clone_upgraded = cloned.upgrade().expect("Could not upgrade weak binder");

        assert_eq!(service, upgraded);
        assert_eq!(service, clone_upgraded);
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn binder_ord() {
        let service1 = BnTest::new_binder(TestService {
            s: "testing_service1".to_string(),
        });
        let service2 = BnTest::new_binder(TestService {
            s: "testing_service2".to_string(),
        });

        assert!(!(service1 < service1));
        assert!(!(service1 > service1));
        assert_eq!(service1 < service2, !(service2 < service1));
    }
}
