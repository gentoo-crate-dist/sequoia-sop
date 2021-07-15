use std::io;

use sequoia_sop as sop;
use sequoia_sop::SOP;
use pyo3::{
    *,
    prelude::*,
    types::*,
};

#[pyclass]
struct SQOP(sop::SQOP<'static>);

#[pymethods]
impl SQOP {
    #[new]
    fn new() -> PyResult<Self> {
        Ok(SQOP(Default::default()))
    }

    /// Returns the version.
    fn version(&self) -> PyResult<Version> {
	let v = self.0.version().map_err(map_err)?;
	Ok(Version {
	    name: v.name(),
	    version: v.version(),
	})
    }

    /// Generates OpenPGP keys.
    #[args(armor = "true", sink = "None")]
    fn generate_key(&self, userids: PyObject, armor: bool, sink: Option<PyObject>) -> PyResult<PyObject> {
	let mut builder = self.0.generate_key().map_err(map_err)?;

	if ! armor {
	    builder = builder.no_armor();
	}

	builder = Python::with_gil(|py| -> PyResult<Box<dyn sop::sop::GenerateKey>> {
	    let userids: &PyAny = userids.as_ref(py);

	    if let Ok(uid) = userids.downcast::<PyString>() {
		builder = builder.userid(uid.to_str()?);
	    } else {
		for uid in userids.iter()? {
		    if let Ok(uid) = uid?.downcast::<PyString>() {
			builder = builder.userid(uid.to_str()?);
		    } else {
			unimplemented!("neither string nor iterable over string")
		    }
		}
	    }

	    Ok(builder)
	})?;

	let ready = builder.generate().map_err(map_err)?;
	handle_result(ready, armor, sink)
    }

    /// Extract a Certificate from a Secret Key.
    #[args(armor = "true", sink = "None")]
    fn extract_cert(&self, key: PyObject, armor: bool, sink: Option<PyObject>) -> PyResult<PyObject> {
	let mut builder = self.0.extract_cert().map_err(map_err)?;

	if ! armor {
	    builder = builder.no_armor();
	}

	let ready = with_source(
	    key,
	    |mut source| builder.key(&mut source).map_err(map_err))?;
	handle_result(ready, armor, sink)
    }
}

/// Handles input given as PyString, PyBytes, or any other Python
/// object implementing the `read` function.
fn with_source<F, T>(source: PyObject, fun: F) -> PyResult<T>
where
    F: FnOnce(&mut (dyn io::Read + Send + Sync)) -> PyResult<T>
{
    Python::with_gil(|py| -> PyResult<T> {
	let source: &PyAny = source.as_ref(py);

	let mut source: Box<dyn io::Read + Send + Sync> =
	    if let Ok(source) = source.downcast::<PyString>() {
		Box::new(io::Cursor::new(source.to_str()?.as_bytes()))
	    } else if let Ok(source) = source.downcast::<PyBytes>() {
		Box::new(io::Cursor::new(source.as_bytes()))
	    } else {
		Box::new(Reader(source.into()))
	    };
	fun(&mut source)
    })
}

/// Streams or converts the result of an operation to Python.
///
/// If sink is Some(_), stream to that sink.  Otherwise, if armor is
/// true, return a PyString, if it is false, return a PyBytes.
fn handle_result<'s>(ready: Box<dyn sop::sop::Ready + 's>,
		     armor: bool,
		     sink: Option<PyObject>)
		     -> PyResult<PyObject> {
    if let Some(sink) = sink {
	let mut writer = Writer(sink);
	ready.write_to(&mut writer).map_err(map_err)?;
	Ok(Python::with_gil(|py| Python::None(py)))
    } else {
	let data = ready.to_vec().map_err(map_err)?;
	Ok(Python::with_gil(|py| {
	    if armor {
		PyString::new(py, &String::from_utf8_lossy(&data))
		    .to_object(py)
	    } else {
		PyBytes::new(py, &data).to_object(py)
	    }
	}))
    }
}

#[pyclass]
struct Version {
    name: String,
    version: String,
}

#[pymethods]
impl Version {
    fn name(&self) -> &str {
	&self.name
    }

    fn version(&self) -> &str {
	&self.version
    }
}

#[pyproto]
impl PyObjectProtocol for Version {
    fn __str__(&self) -> String {
	format!("{} {}", self.name, self.version)
    }
}

/// Wrapped Python writer.
struct Writer(PyObject);

impl io::Write for Writer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
	Python::with_gil(|py| -> PyResult<usize> {
	    let buf = PyBytes::new(py, &buf);
	    let written = self.0.call_method1(py, "write", (buf, ))?;
	    written.extract(py)
	}).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    fn flush(&mut self) -> io::Result<()> {
	Python::with_gil(|py| -> PyResult<()> {
	    self.0.call_method0(py, "flush")?;
	    Ok(())
	}).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

/// Wrapped Python reader.
struct Reader(PyObject);

impl io::Read for Reader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
	Python::with_gil(|py| -> PyResult<usize> {
	    //let len = PyInt::new(py, buf.len().try_into()?);
	    let read = self.0.call_method1(py, "read1", (buf.len(), ))?;
	    // XXX: Avoid the copy using `readinto`.

	    if let Ok(r) = read.cast_as::<PyBytes>(py) {
		// XXX: Handle the case that read is larger than buf.
		let l = buf.len().min(r.as_bytes().len());
		buf[..l].copy_from_slice(&r.as_bytes()[..l]);
		Ok(l)
	    } else {
		unimplemented!("Expected bytes object, got {:?}", read)
	    }
	}).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

create_exception!(module, SopError, pyo3::exceptions::PyException);

fn map_err(e: sop::sop::Error) -> PyErr {
    SopError::new_err(e.to_string())
}

/// A Python module implemented in Rust.
#[pymodule]
fn py_sequoia_sop(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<SQOP>()?;
    m.add_class::<Version>()?;
    m.add("SopError", py.get_type::<SopError>())?;

    Ok(())
}
