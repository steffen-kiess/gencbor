gencbor
=======

This is a simple generic [CBOR (RFC8949)][RFC8949] encoder / decoder which
will not look at any tag values.

[RFC8949]: https://datatracker.ietf.org/doc/html/rfc8949

How to use
----------

```
>>> import gencbor
>>> gencbor.encode(gencbor.Tag(0x1001, [3, 4, 5]))
b'\xd9\x10\x01\x83\x03\x04\x05'
>>> gencbor.decode(b'\xd9\x10\x01\x83\x03\x04\x05')
Tag(4097, (3, 4, 5))
>>> gencbor.encode(gencbor.Map([(0, 'int'), (0.0, 'float')]))
b'\xa2\x00cint\xf9\x00\x00efloat'
>>> gencbor.decode(gencbor.encode(gencbor.Map([(0, 'int'), (0.0, 'float')])))
Map({0: int, 0.0: float})
>>> gencbor.decode(gencbor.encode([gencbor.SimpleValue(i) for i in range(18, 24)]))
(SimpleValue(18), SimpleValue(19), False, True, None, undefined)
>>> 
```

General
-------

- The library is will treat `0` and `0.0` as distinct, i.e. both values can be
  in keys in the same map.

- The library is also supposed to treat different `nan` values as different,
  but currently there is a bug when encoding non-standard `nan` values.

- The library will check for well-formed-ness and for
  [basic validity][RFC8949-5.3.1]. It will not check for tag validity.

- `false`, `true` and `null` will by default be decoded to `False`, `True` and
  `None`.

[RFC8949-5.3.1]: https://datatracker.ietf.org/doc/html/rfc8949#section-5.3.1
