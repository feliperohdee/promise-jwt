const assert = require('assert');
const {
    decode,
    sign,
    verify
} = require('./');

const secret = 'mySecret';
const jwt = sign({
    role: 'admin',
    user: 'admin'
}, secret);

// should decode
jwt.then(token => {
        return decode(token, secret);
    })
    .then(payload => {
        assert.deepStrictEqual(payload, {
            role: 'admin',
            user: 'admin',
            iat: payload.iat
        });
    });

// should verify
jwt.then(token => {
        return verify(token, secret);
    })
    .then(payload => {
        assert.deepStrictEqual(payload, {
            role: 'admin',
            user: 'admin',
            iat: payload.iat
        });
    });

// handle invalid signature
jwt.then(token => {
        return verify(token, 'wrongSectet');
    })
    .catch(err => {
        assert.strictEqual(err.message, 'invalid signature');
    });