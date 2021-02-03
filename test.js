const assert = require('assert');
const {
    decode,
    sign,
    verify
} = require('./');

const secret = 'mySecret';

(async () => {
    let token = await sign({
        role: 'admin',
        user: 'admin'
    }, secret);

    // should decode
    let payload = decode(token);

    assert.deepStrictEqual(payload, {
        role: 'admin',
        user: 'admin',
        iat: payload.iat
    });

    // should verify
    payload = await verify(token, secret);

    assert.deepStrictEqual(payload, {
        role: 'admin',
        user: 'admin',
        iat: payload.iat
    });

    // should handle invalid signature
    try {
        payload = await verify(token, 'wrongSecret');
    } catch (err) {
        assert.strictEqual(err.message, 'invalid signature');
    }

    // should handle expired token
    token = await sign({
        role: 'admin',
        user: 'admin'
    }, secret, {
        expiresIn: -1
    });

    try {
        payload = await verify(token, secret);
    } catch (err) {
        assert.strictEqual(err.message, 'jwt expired');
    }
})();