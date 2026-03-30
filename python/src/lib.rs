#![forbid(unsafe_code)]

use std::{collections::HashMap, sync::Arc};

use pyo3::{
    exceptions::{PyRuntimeError, PyValueError},
    prelude::*,
    types::PyBytes,
};
use pyo3_async_runtimes::tokio::future_into_py;

fn convert_error(err: oo7_rs::Error) -> PyErr {
    PyRuntimeError::new_err(format!("oo7 error: {:?}", err))
}

#[derive(Clone)]
struct SecretBytes(Vec<u8>);

impl<'py> IntoPyObject<'py> for SecretBytes {
    type Target = PyBytes;
    type Output = Bound<'py, Self::Target>;
    type Error = std::convert::Infallible;

    fn into_pyobject(self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
        Ok(PyBytes::new(py, &self.0))
    }
}

fn python_to_secret(obj: &Bound<PyAny>) -> PyResult<oo7_rs::Secret> {
    if let Ok(bytes) = obj.extract::<Vec<u8>>() {
        Ok(oo7_rs::Secret::from(bytes))
    } else if let Ok(text) = obj.extract::<String>() {
        Ok(oo7_rs::Secret::text(&text))
    } else {
        Err(PyValueError::new_err("Secret must be either bytes or str"))
    }
}

#[pyclass]
struct Keyring {
    inner: Arc<oo7_rs::Keyring>,
}

#[pymethods]
impl Keyring {
    #[staticmethod]
    #[pyo3(name = "new")]
    fn create(py: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
        future_into_py(py, async move {
            let keyring = oo7_rs::Keyring::new().await.map_err(convert_error)?;
            Ok(Keyring {
                inner: Arc::new(keyring),
            })
        })
    }

    fn unlock<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let inner = Arc::clone(&self.inner);
        future_into_py(py, async move {
            inner.unlock().await.map_err(convert_error)?;
            Ok(())
        })
    }

    fn lock<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let inner = Arc::clone(&self.inner);
        future_into_py(py, async move {
            inner.lock().await.map_err(convert_error)?;
            Ok(())
        })
    }

    fn is_locked<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let inner = Arc::clone(&self.inner);
        future_into_py(py, async move {
            let locked = inner.is_locked().await.map_err(convert_error)?;
            Ok(locked)
        })
    }

    fn delete<'p>(
        &self,
        py: Python<'p>,
        attributes: HashMap<String, String>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let inner = Arc::clone(&self.inner);
        future_into_py(py, async move {
            inner.delete(&attributes).await.map_err(convert_error)?;
            Ok(())
        })
    }

    fn items<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let inner = Arc::clone(&self.inner);
        future_into_py(py, async move {
            let items = inner.items().await.map_err(convert_error)?;
            let py_items: Vec<Item> = items
                .into_iter()
                .map(|item| Item {
                    inner: Arc::new(item),
                })
                .collect();
            Ok(py_items)
        })
    }

    fn create_item<'p>(
        &self,
        py: Python<'p>,
        label: String,
        attributes: HashMap<String, String>,
        secret: &Bound<'p, PyAny>,
        replace: bool,
    ) -> PyResult<Bound<'p, PyAny>> {
        let inner = Arc::clone(&self.inner);
        let secret = python_to_secret(secret)?;

        future_into_py(py, async move {
            inner
                .create_item(&label, &attributes, secret, replace)
                .await
                .map_err(convert_error)?;
            Ok(())
        })
    }

    fn search_items<'p>(
        &self,
        py: Python<'p>,
        attributes: HashMap<String, String>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let inner = Arc::clone(&self.inner);
        future_into_py(py, async move {
            let items = inner
                .search_items(&attributes)
                .await
                .map_err(convert_error)?;
            let py_items: Vec<Item> = items
                .into_iter()
                .map(|item| Item {
                    inner: Arc::new(item),
                })
                .collect();
            Ok(py_items)
        })
    }
}

#[pyclass]
struct Item {
    inner: Arc<oo7_rs::Item>,
}

#[pymethods]
impl Item {
    fn label<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let inner = Arc::clone(&self.inner);
        future_into_py(py, async move {
            let label = inner.label().await.map_err(convert_error)?;
            Ok(label)
        })
    }

    fn set_label<'p>(&self, py: Python<'p>, label: String) -> PyResult<Bound<'p, PyAny>> {
        let inner = Arc::clone(&self.inner);
        future_into_py(py, async move {
            inner.set_label(&label).await.map_err(convert_error)?;
            Ok(())
        })
    }

    fn attributes<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let inner = Arc::clone(&self.inner);
        future_into_py(py, async move {
            let attrs = inner.attributes().await.map_err(convert_error)?;
            Ok(attrs)
        })
    }

    fn set_attributes<'p>(
        &self,
        py: Python<'p>,
        attributes: HashMap<String, String>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let inner = Arc::clone(&self.inner);
        future_into_py(py, async move {
            inner
                .set_attributes(&attributes)
                .await
                .map_err(convert_error)?;
            Ok(())
        })
    }

    fn secret<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let inner = Arc::clone(&self.inner);
        future_into_py(py, async move {
            let secret = inner.secret().await.map_err(convert_error)?;
            let bytes = SecretBytes(secret.as_bytes().to_vec());
            Ok(bytes)
        })
    }

    fn set_secret<'p>(
        &self,
        py: Python<'p>,
        secret: &Bound<'p, PyAny>,
    ) -> PyResult<Bound<'p, PyAny>> {
        let inner = Arc::clone(&self.inner);
        let secret = python_to_secret(secret)?;

        future_into_py(py, async move {
            inner.set_secret(secret).await.map_err(convert_error)?;
            Ok(())
        })
    }

    fn is_locked<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let inner = Arc::clone(&self.inner);
        future_into_py(py, async move {
            let locked = inner.is_locked().await.map_err(convert_error)?;
            Ok(locked)
        })
    }

    fn lock<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let inner = Arc::clone(&self.inner);
        future_into_py(py, async move {
            inner.lock().await.map_err(convert_error)?;
            Ok(())
        })
    }

    fn unlock<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let inner = Arc::clone(&self.inner);
        future_into_py(py, async move {
            inner.unlock().await.map_err(convert_error)?;
            Ok(())
        })
    }

    fn delete<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let inner = Arc::clone(&self.inner);
        future_into_py(py, async move {
            inner.delete().await.map_err(convert_error)?;
            Ok(())
        })
    }

    fn created<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let inner = Arc::clone(&self.inner);
        future_into_py(py, async move {
            let duration = inner.created().await.map_err(convert_error)?;
            Ok(duration.as_secs_f64())
        })
    }

    fn modified<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let inner = Arc::clone(&self.inner);
        future_into_py(py, async move {
            let duration = inner.modified().await.map_err(convert_error)?;
            Ok(duration.as_secs_f64())
        })
    }
}

#[pymodule]
fn oo7(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Keyring>()?;
    m.add_class::<Item>()?;
    Ok(())
}
