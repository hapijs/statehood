'use strict';

const Code = require('@hapi/code');
const Cryptiles = require('@hapi/cryptiles');
const Iron = require('@hapi/iron');
const Lab = require('@hapi/lab');
const Statehood = require('..');


const internals = {};


const { describe, it } = exports.lab = Lab.script();
const expect = Code.expect;


describe('Definitions', () => {

    const password = 'a_password_that_is_not_too_short_and_also_not_very_random_but_is_good_enough';

    describe('add()', () => {

        it('throws on missing name', () => {

            const definitions = new Statehood.Definitions();
            expect(() => {

                definitions.add();
            }).to.throw('Invalid name');
        });

        it('uses defaults', () => {

            const definitions = new Statehood.Definitions();
            definitions.add('test');
            expect(definitions.cookies.test).to.equal({
                strictHeader: true,
                ignoreErrors: false,
                isSecure: true,
                isHttpOnly: true,
                isSameSite: 'Strict',
                path: null,
                domain: null,
                ttl: null,
                encoding: 'none'
            });
        });

        it('records name', () => {

            const definitions = new Statehood.Definitions();
            definitions.add('test');
            expect(definitions.names).to.equal(['test']);
        });

        it('adds definition with null value', () => {

            const definitions = new Statehood.Definitions({ path: '/' });

            definitions.add('base');
            expect(definitions.cookies.base.path).to.equal('/');

            definitions.add('test', { path: null });
            expect(definitions.cookies.test.path).to.equal(null);
        });
    });

    describe('parse()', () => {

        it('parses cookie', async () => {

            const definitions = new Statehood.Definitions();
            const { states, failed } = await definitions.parse('a=b');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ a: 'b' });
        });

        it('parses cookie (loose)', async () => {

            const definitions = new Statehood.Definitions({ strictHeader: false });
            const { states, failed } = await definitions.parse('a="1; b="2"; c=3; d[1]=4;=1');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ a: '"1', b: '2', c: '3', 'd[1]': '4', '': '1' });
        });

        it('parses cookie (none)', async () => {

            const definitions = new Statehood.Definitions();
            const { states, failed } = await definitions.parse('');
            expect(failed).to.have.length(0);
            expect(states).to.equal({});
        });

        it('parses cookie (empty)', async () => {

            const definitions = new Statehood.Definitions();
            const { states, failed } = await definitions.parse('a=');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ a: '' });
        });

        it('parses cookie (quoted empty)', async () => {

            const definitions = new Statehood.Definitions();
            const { states, failed } = await definitions.parse('a=""');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ a: '' });
        });

        it('parses cookie (semicolon single)', async () => {

            const definitions = new Statehood.Definitions();
            const { states, failed } = await definitions.parse('a=;');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ a: '' });
        });

        it('parses cookie (number)', async () => {

            const definitions = new Statehood.Definitions();
            const { states, failed } = await definitions.parse('a=23');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ a: '23' });
        });

        it('parses cookie (array)', async () => {

            const definitions = new Statehood.Definitions();
            const { states, failed } = await definitions.parse('a=1; a=2');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ a: ['1', '2'] });
        });

        it('parses cookie (mixed style array)', async () => {

            const definitions = new Statehood.Definitions();
            const { states, failed } = await definitions.parse('a=1; b="2"; c=3');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ a: '1', b: '2', c: '3' });
        });

        it('parses cookie (mixed style array quoted first)', async () => {

            const definitions = new Statehood.Definitions();
            const { states, failed } = await definitions.parse('a="1"; b="2"; c=3');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ a: '1', b: '2', c: '3' });
        });

        it('parses cookie (white space)', async () => {

            const definitions = new Statehood.Definitions();
            const { states, failed } = await definitions.parse('A    = b;   b  =   c');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ A: 'b', b: 'c' });
        });

        it('parses cookie (raw form)', async () => {

            const definitions = new Statehood.Definitions();
            const { states, failed } = await definitions.parse('a="b=123456789&c=something"');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ a: 'b=123456789&c=something' });
        });

        it('parses cookie (raw percent)', async () => {

            const definitions = new Statehood.Definitions();
            const { states, failed } = await definitions.parse('a=%1;b=x');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ a: '%1', b: 'x' });
        });

        it('parses cookie (raw encoded)', async () => {

            const definitions = new Statehood.Definitions();
            const { states, failed } = await definitions.parse('z=%20%22%2c%3b%2f');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ z: '%20%22%2c%3b%2f' });
        });

        it('parses cookie (form single)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('a', { encoding: 'form' });
            const { states, failed } = await definitions.parse('a="b=%p123456789"');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ a: { b: '%p123456789' } });
        });

        it('parses cookie (form multiple)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('a', { encoding: 'form' });
            const { states, failed } = await definitions.parse('a="b=123456789&c=something%20else"');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ a: { b: '123456789', c: 'something else' } });
        });

        it('parses cookie with an empty key-value on non-strict header (form single)', async () => {

            const definitions = new Statehood.Definitions({ strictHeader: false, encoding: 'form' });
            const { states, failed } = await definitions.parse('=');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ '': {} });
        });

        it('parses cookie (base64 array 2)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('a', { encoding: 'base64' });
            const { states, failed } = await definitions.parse('a=dGVzdA; a=dGVzdA');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ a: ['test', 'test'] });
        });

        it('parses cookie (base64 array 3)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('a', { encoding: 'base64' });
            const { states, failed } = await definitions.parse('a=dGVzdA; a=dGVzdA; a=dGVzdA');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ a: ['test', 'test', 'test'] });
        });

        it('parses cookie (base64 padding)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('key', { encoding: 'base64' });
            const { states, failed } = await definitions.parse('key=dGVzdA==');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ key: 'test' });
        });

        it('parses cookie (base64, empty)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('key', { encoding: 'base64' });
            const { states, failed } = await definitions.parse('key=');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ key: '' });
        });

        it('parses cookie (base64)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('key', { encoding: 'base64' });
            const { states, failed } = await definitions.parse('key=dGVzdA');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ key: 'test' });
        });

        it('parses cookie (none encoding)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('key', { encoding: 'none' });
            const { states, failed } = await definitions.parse('key=dGVzdA');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ key: 'dGVzdA' });
        });

        it('parses cookie with an empty key-value on non-strict header (none encoding)', async () => {

            const definitions = new Statehood.Definitions({ strictHeader: false, encoding: 'none' });
            const { states, failed } = await definitions.parse('=');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ '': '' });
        });

        it('parses cookie (base64json)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('key', { encoding: 'base64json' });
            const { states, failed } = await definitions.parse('key=eyJ0ZXN0aW5nIjoianNvbiJ9');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ key: { testing: 'json' } });
        });

        it('parses cookie (iron)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('key', { encoding: 'iron', password });
            const { states, failed } = await definitions.parse('key=Fe26.2**8ec29d2e64ab19a0429faab76c46167c933b7c2c94dac8022bb4c97de0fc359d*O2aDw2nk5Svfc4xiuatycw*DWWOPpI3-B6Bb4oOOuNxGT8v9S4jZ_hpQZaaeYREvuk**34d98c193fd2048b40655966115d75dae62aab96cd1f5b374908b86fc47a61d3*H_zsHSt6UoOj3QgBIuNMrNHAUosM6Sp51uLKak0ZUjg');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ key: { a: 1, b: 2, c: 3 } });
        });

        it('parses cookie (iron settings)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('key', { encoding: 'iron', password, iron: Iron.defaults });
            const { states, failed } = await definitions.parse('key=Fe26.2**8ec29d2e64ab19a0429faab76c46167c933b7c2c94dac8022bb4c97de0fc359d*O2aDw2nk5Svfc4xiuatycw*DWWOPpI3-B6Bb4oOOuNxGT8v9S4jZ_hpQZaaeYREvuk**34d98c193fd2048b40655966115d75dae62aab96cd1f5b374908b86fc47a61d3*H_zsHSt6UoOj3QgBIuNMrNHAUosM6Sp51uLKak0ZUjg');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ key: { a: 1, b: 2, c: 3 } });
        });

        it('parses cookie (iron array)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('key', { encoding: 'iron', password, iron: Iron.defaults });
            const { states, failed } = await definitions.parse('key=Fe26.2**b2c8dd90b7d90d6881b28577ae26a3b001da4692d5158a3356cdb3e3226bd4d5*GluKNAVi_H6EvyNo-pPZAg*VTdzi3c2EdE7keMpJ7bWeQ**10b30a3b217af99c4ce0e9bd2b7060f0d0cebc8a4c2d26057d83c5c6f62606f6*KO6neEo8gdifE8zPNXCGZvgAzmHSrm64ECSHc2fAOqA; key=Fe26.2**f2a33694ff42a7f9b1c2539f798e482fc6abcb4dc4010bff0ebe08531642c086*4jkWFlBPCUzkNP-cCi5Vuw*9Dl2y0PJ5VngIg6jw9Ai3w**ac5c2f209e115b530fe2765471452a51eee169951d56724148ec57dcf7f37fa1*khzOdma_xHnnkcLsAiF58vyOMxmiDvJakLH0WfKkN9E');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ key: ['test1', 'test2'] });
        });

        it('parses cookie (iron array with one valid and one invalid)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('key', { encoding: 'iron', password, iron: Iron.defaults });
            const err = await expect(definitions.parse('key=Fe26.2**e20b0f5870eef8bde58e79dd7b18ac1741e96058a767f01567ec81e61e02c365*OVMU0-_gQzItLkQrG1wtCQ*eDtH5LFkLJ1bu_kMiOna7A**df5ec6b468f5aef7a5c93794fc346852ef143fe10dd01a8af255fb2ed3a6eefd*EaoDWDDzA1GOJN8bg607JhX8Us5XTo7Xqvr-YBECxes; key=Fe26.2**e3bb1ff096f1f6cc39f02198617dedc0bb0f3db2090ecffe54c4e0d7f05071d5*WWCR6HVELSszlgVQKeJwkg*UHeqS46TMQsmNK_nmY8aug**aae27037c2588341fc0649db9335bf18a9b9bb1589cf4e6721ec4a6212d4a82a*ZOJXMFRbbaP-1VL6FK4zuris-CJDXuuMamRTXkTw_ZM')).to.reject();
            expect(err.failed).to.have.length(1);
            expect(err.states).to.equal({ key: ['good'] });
        });

        it('parses cookie (signed form)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('sid', { encoding: 'form', sign: { password } });

            const { states, failed } = await definitions.parse('sid=a=1&b=2&c=3%20x.2d75635d74c1a987f84f3ee7f3113b9a2ff71f89d6692b1089f19d5d11d140f8*anm-37hjjRC3eY7Mcv4gP7gXgXBKTtUz9fNFWnetEZo');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ sid: { a: '1', b: '2', c: '3 x' } });
        });

        it('parses cookie (signed form integrity settings)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('sid', { encoding: 'form', sign: { password, integrity: Iron.defaults.integrity } });
            const { states, failed } = await definitions.parse('sid=a=1&b=2&c=3%20x.2d75635d74c1a987f84f3ee7f3113b9a2ff71f89d6692b1089f19d5d11d140f8*anm-37hjjRC3eY7Mcv4gP7gXgXBKTtUz9fNFWnetEZo');
            expect(failed).to.have.length(0);
            expect(states.sid).to.equal({ a: '1', b: '2', c: '3 x' });
            expect(states).to.equal({ sid: { a: '1', b: '2', c: '3 x' } });
        });

        it('parses cookie (cookie level strict override)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('a', { strictHeader: false });
            const { states, failed } = await definitions.parse('a="1');
            expect(failed).to.have.length(0);
            expect(states).to.equal({ a: '"1' });
        });

        it('fails parsing cookie (mismatching quotes)', async () => {

            const definitions = new Statehood.Definitions();
            const err = await expect(definitions.parse('a="1; b="2"; c=3')).to.reject();

            expect(err.data).to.equal([
                {
                    name: 'a',
                    value: '"1',
                    settings: {
                        isSecure: true,
                        isHttpOnly: true,
                        isSameSite: 'Strict',
                        path: null,
                        domain: null,
                        ttl: null,
                        encoding: 'none',
                        strictHeader: true,
                        ignoreErrors: false
                    },
                    reason: 'Invalid cookie value'
                }
            ]);

            expect(err.failed).to.equal(err.data);
        });

        it('ignores failed parsing cookie (mismatching quotes)', async () => {

            const definitions = new Statehood.Definitions({ ignoreErrors: true });
            const { failed } = await definitions.parse('a="1; b="2"; c=3');
            expect(failed).to.equal([
                {
                    name: 'a',
                    value: '"1',
                    settings: {
                        isSecure: true,
                        isHttpOnly: true,
                        isSameSite: 'Strict',
                        path: null,
                        domain: null,
                        ttl: null,
                        encoding: 'none',
                        strictHeader: true,
                        ignoreErrors: true
                    },
                    reason: 'Invalid cookie value'
                }
            ]);
        });

        it('ignores failed parsing cookie (cookie settings)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('a', { ignoreErrors: true });
            await expect(definitions.parse('a="1')).to.not.reject();
        });

        it('fails parsing cookie (name)', async () => {

            const definitions = new Statehood.Definitions();
            const err = await expect(definitions.parse('a@="1"; b="2"; c=3')).to.reject();
            expect(err.data).to.equal([
                {
                    name: 'a@',
                    value: '1',
                    settings: {
                        isSecure: true,
                        isHttpOnly: true,
                        isSameSite: 'Strict',
                        path: null,
                        domain: null,
                        ttl: null,
                        encoding: 'none',
                        strictHeader: true,
                        ignoreErrors: false
                    },
                    reason: 'Invalid cookie name'
                }
            ]);
        });

        it('fails parsing cookie (multiple)', async () => {

            const definitions = new Statehood.Definitions();
            const err = await expect(definitions.parse('a@="1"; b@="2"; c=3')).to.reject();
            expect(err.data).to.equal([
                {
                    name: 'a@',
                    value: '1',
                    settings: {
                        isSecure: true,
                        isHttpOnly: true,
                        isSameSite: 'Strict',
                        path: null,
                        domain: null,
                        ttl: null,
                        encoding: 'none',
                        strictHeader: true,
                        ignoreErrors: false
                    },
                    reason: 'Invalid cookie name'
                },
                {
                    name: 'b@',
                    value: '2',
                    settings: {
                        isSecure: true,
                        isHttpOnly: true,
                        isSameSite: 'Strict',
                        path: null,
                        domain: null,
                        ttl: null,
                        encoding: 'none',
                        strictHeader: true,
                        ignoreErrors: false
                    },
                    reason: 'Invalid cookie name'
                }
            ]);
        });

        it('ignores failed parsing cookie (name)', async () => {

            const definitions = new Statehood.Definitions({ ignoreErrors: true });
            await expect(definitions.parse('a@="1"; b="2"; c=3')).to.not.reject();
        });

        it('fails parsing cookie (empty pair)', async () => {

            const definitions = new Statehood.Definitions();
            await expect(definitions.parse('a=1; b=2; c=3;;')).to.reject('Invalid cookie header');
        });

        it('fails parsing cookie (empty pair, ignoring errors)', async () => {

            const definitions = new Statehood.Definitions({ ignoreErrors: true });
            const { states, failed } = await definitions.parse('a=1; b=2; c=3;;');
            expect(states).to.equal({ a: '1', b: '2', c: '3' });
            expect(failed).to.equal([
                {
                    settings: {
                        isSecure: true,
                        isHttpOnly: true,
                        isSameSite: 'Strict',
                        path: null,
                        domain: null,
                        ttl: null,
                        encoding: 'none',
                        strictHeader: true,
                        ignoreErrors: true
                    },
                    reason: 'Header contains unexpected syntax: ;'
                }
            ]);
        });

        it('fails parsing cookie (missing values, ignoring errors)', async () => {

            const definitions = new Statehood.Definitions({ ignoreErrors: true });
            const { states, failed } = await definitions.parse('a=1; b=2; c=3;qrs;tuv');
            expect(states).to.equal({ a: '1', b: '2', c: '3' });
            expect(failed).to.equal([
                {
                    settings: {
                        isSecure: true,
                        isHttpOnly: true,
                        isSameSite: 'Strict',
                        path: null,
                        domain: null,
                        ttl: null,
                        encoding: 'none',
                        strictHeader: true,
                        ignoreErrors: true
                    },
                    reason: 'Header contains unexpected syntax: qrs;tuv'
                }
            ]);
        });

        it('fails parsing cookie (base64json)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('x', { encoding: 'base64json' });
            const err = await expect(definitions.parse('x=XeyJ0ZXN0aW5nIjoianNvbiJ9')).to.reject('Invalid cookie value');
            expect(err.data).to.equal([
                {
                    name: 'x',
                    value: 'XeyJ0ZXN0aW5nIjoianNvbiJ9',
                    settings: {
                        strictHeader: true,
                        ignoreErrors: false,
                        isSecure: true,
                        isHttpOnly: true,
                        isSameSite: 'Strict',
                        path: null,
                        domain: null,
                        ttl: null,
                        encoding: 'base64json'
                    },
                    reason: err.data[0].reason
                }
            ]);
        });

        it('fails parsing cookie (base64json with proto)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('x', { encoding: 'base64json' });
            await expect(definitions.parse('x=eyAiYSI6IDUsICJiIjogNiwgIl9fcHJvdG9fXyI6IHsgIngiOiA3IH0gfQ')).to.reject('Invalid cookie value');
        });

        it('ignores failed parsing cookie (base64json)', async () => {

            const definitions = new Statehood.Definitions({ ignoreErrors: true });
            definitions.add('x', { encoding: 'base64json' });
            await expect(definitions.parse('x=XeyJ0ZXN0aW5nIjoianNvbiJ9')).to.not.reject();
        });

        it('fails parsing cookie (double base64json)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('x', { encoding: 'base64json' });
            await expect(definitions.parse('x=XeyJ0ZXN0aW5nIjoianNvbiJ9; x=XeyJ0ZXN0aW5dnIjoianNvbiJ9')).to.reject('Invalid cookie value');
        });

        it('ignores failed parsing cookie (double base64json)', async () => {

            const definitions = new Statehood.Definitions({ ignoreErrors: true });
            definitions.add('x', { encoding: 'base64json' });
            await expect(definitions.parse('x=XeyJ0ZXN0aW5nIjoianNvbiJ9; x=XeyJ0ZXN0aW5dnIjoianNvbiJ9')).to.not.reject();
        });

        it('fails parsing cookie (iron)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('key', { encoding: 'iron', password });
            await expect(definitions.parse('key=Fe26.1**f3fc42242467f7a97c042be866a32c1e7645045c2cc085124eadc66d25fc8395*URXpH8k-R0d4O5bnY23fRQ*uq9rd8ZzdjZqUrq9P2Ci0yZ-EEUikGzxTLn6QTcJ0bc**3880c0ac8bab054f529afec8660ebbbbc8050e192e39e5d622e7ac312b9860d0*r_g7N9kJYqXDrFlvOnuKpfpEWwrJLOKMXEI43LAGeFg')).to.reject('Invalid cookie value');
        });

        it('fails parsing cookie (iron password)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('key', { encoding: 'iron', password: 'passwordx' });
            await expect(definitions.parse('key=Fe26.2**f3fc42242467f7a97c042be866a32c1e7645045c2cc085124eadc66d25fc8395*URXpH8k-R0d4O5bnY23fRQ*uq9rd8ZzdjZqUrq9P2Ci0yZ-EEUikGzxTLn6QTcJ0bc**3880c0ac8bab054f529afec8660ebbbbc8050e192e39e5d622e7ac312b9860d0*r_g7N9kJYqXDrFlvOnuKpfpEWwrJLOKMXEI43LAGeFg')).to.reject('Invalid cookie value');
        });

        it('fails parsing cookie (signed form missing options)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('sid', { encoding: 'form', sign: {} });
            await expect(definitions.parse('sid=a=1&b=2&c=3%20x.2d75635d74c1a987f84f3ee7f3113b9a2ff71f89d6692b1089f19d5d11d140f8*khsb8lmkNJS-iljqDKZDMmd__2PcHBz7Ksrc-48gZ-0')).to.reject('Invalid cookie value');
        });

        it('fails parsing cookie (signed form missing signature)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('sid', { encoding: 'form', sign: { password } });
            await expect(definitions.parse('sid=a=1&b=2&c=3%20x')).to.reject('Invalid cookie value');
        });

        it('ignores failed parsing cookie (signed form missing signature)', async () => {

            const definitions = new Statehood.Definitions({ ignoreErrors: true });
            definitions.add('sid', { encoding: 'form', sign: { password } });
            await expect(definitions.parse('sid=a=1&b=2&c=3%20x')).to.not.reject();
        });

        it('fails parsing cookie (signed form missing signature double)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('sid', { encoding: 'form', sign: { password } });
            await expect(definitions.parse('sid=a=1&b=2&c=3%20x; sid=a=1&b=2&c=3%20x')).to.reject('Invalid cookie value');
        });

        it('ignores failed parsing cookie (signed form missing signature double)', async () => {

            const definitions = new Statehood.Definitions({ ignoreErrors: true });
            definitions.add('sid', { encoding: 'form', sign: { password } });
            await expect(definitions.parse('sid=a=1&b=2&c=3%20x; sid=a=1&b=2&c=3%20x')).to.not.reject();
        });

        it('fails parsing cookie (signed form missing signature with sep)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('sid', { encoding: 'form', sign: { password } });
            await expect(definitions.parse('sid=a=1&b=2&c=3%20x.')).to.reject('Invalid cookie value');
        });

        it('fails parsing cookie (signed form invalid signature)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('sid', { encoding: 'form', sign: { password } });
            await expect(definitions.parse('sid=a=1&b=2&c=3%20x.2d75635d74c1a987f84f3ee7f3113b9a2ff71f89d6692b1089f19d5d11d140f8')).to.reject('Invalid cookie value');
        });

        it('fails parsing cookie (signed form wrong signature)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('sid', { encoding: 'form', sign: { password } });
            await expect(definitions.parse('sid=a=1&b=2&c=3%20x.2d75635d74c1a987f84f3ee7f3113b9a2ff71f89d6692b1089f19d5d11d140f8*-Ghc6WvkE55V-TzucCl0NVFmbijeCwgs5Hf5tAVbSUo')).to.reject('Invalid cookie value');
        });

        it('errors on __proto__ cookie', async () => {

            const definitions = new Statehood.Definitions();
            await expect(definitions.parse('__proto__=b')).to.reject('Invalid cookie header');
        });
    });

    describe('format()', () => {

        it('skips an empty header', async () => {

            const definitions = new Statehood.Definitions();
            const header = await definitions.format(null);
            expect(header).to.equal([]);
        });

        it('skips an empty array', async () => {

            const definitions = new Statehood.Definitions();
            const header = await definitions.format([]);
            expect(header).to.equal([]);
        });

        it('formats a header', async () => {

            const definitions = new Statehood.Definitions();
            const header = await definitions.format({ name: 'sid', value: 'fihfieuhr9384hf', options: { ttl: 3600, isSameSite: 'Lax', path: '/', domain: 'example.com' } });
            const expires = new Date(Date.now() + 3600);
            expect(header[0]).to.equal('sid=fihfieuhr9384hf; Max-Age=3; Expires=' + expires.toUTCString() + '; Secure; HttpOnly; SameSite=Lax; Domain=example.com; Path=/');
        });

        it('formats a header (SameSite: None)', async () => {

            const definitions = new Statehood.Definitions();
            const header = await definitions.format({ name: 'sid', value: 'fihfieuhr9384hf', options: { ttl: 3600, isSameSite: 'None', path: '/', domain: 'example.com' } });
            const expires = new Date(Date.now() + 3600);
            expect(header[0]).to.equal('sid=fihfieuhr9384hf; Max-Age=3; Expires=' + expires.toUTCString() + '; Secure; HttpOnly; SameSite=None; Domain=example.com; Path=/');
        });

        it('formats a header (contextualize)', async () => {

            const definitions = new Statehood.Definitions();
            const contextualize = (definition, context) => {

                definition.isSameSite = context;
            };

            const header = await definitions.format({ name: 'sid', value: 'fihfieuhr9384hf', options: { ttl: 3600, contextualize, path: '/', domain: 'example.com' } }, 'TEST');
            const expires = new Date(Date.now() + 3600);
            expect(header[0]).to.equal('sid=fihfieuhr9384hf; Max-Age=3; Expires=' + expires.toUTCString() + '; Secure; HttpOnly; SameSite=TEST; Domain=example.com; Path=/');
        });

        it('formats a header (contextualize with defaults)', async () => {

            const contextualize = (definition, context) => {

                definition.isSameSite = context;
            };

            const definitions = new Statehood.Definitions({ ttl: 3600, contextualize, path: '/', domain: 'example.com' });

            const header = await definitions.format({ name: 'sid', value: 'fihfieuhr9384hf' }, 'TEST');
            const expires = new Date(Date.now() + 3600);
            expect(header[0]).to.equal('sid=fihfieuhr9384hf; Max-Age=3; Expires=' + expires.toUTCString() + '; Secure; HttpOnly; SameSite=TEST; Domain=example.com; Path=/');

            expect(definitions.settings.isSameSite).to.equal('Strict');
        });

        it('formats a header (with null ttl)', async () => {

            const definitions = new Statehood.Definitions({ ttl: 3600 });
            const header = await definitions.format({ name: 'sid', value: 'fihfieuhr9384hf', options: { ttl: null, path: '/', domain: 'example.com' } });
            expect(header[0]).to.equal('sid=fihfieuhr9384hf; Secure; HttpOnly; SameSite=Strict; Domain=example.com; Path=/');
        });

        it('formats a header (with explicitly undefined ttl)', async () => {

            const definitions = new Statehood.Definitions({ ttl: 3600 });
            const header = await definitions.format({ name: 'sid', value: 'fihfieuhr9384hf', options: { ttl: undefined, path: '/', domain: 'example.com' } });
            expect(header[0]).to.equal('sid=fihfieuhr9384hf; Secure; HttpOnly; SameSite=Strict; Domain=example.com; Path=/');
        });

        it('formats a header (with zero ttl)', async () => {

            const definitions = new Statehood.Definitions();
            const header = await definitions.format({ name: 'sid', value: 'fihfieuhr9384hf', options: { ttl: 0, path: '/', domain: 'example.com' } });
            expect(header[0]).to.equal('sid=fihfieuhr9384hf; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Strict; Domain=example.com; Path=/');
        });

        it('formats a header with null value', async () => {

            const definitions = new Statehood.Definitions();
            const header = await definitions.format({ name: 'sid', options: { ttl: 3600, path: '/', domain: 'example.com' } });
            const expires = new Date(Date.now() + 3600);
            expect(header[0]).to.equal('sid=; Max-Age=3; Expires=' + expires.toUTCString() + '; Secure; HttpOnly; SameSite=Strict; Domain=example.com; Path=/');
        });

        it('formats a header with server definition', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('sid', { ttl: 3600, path: '/', domain: 'example.com' });
            const header = await definitions.format({ name: 'sid', value: 'fihfieuhr9384hf' });
            const expires = new Date(Date.now() + 3600);
            expect(header[0]).to.equal('sid=fihfieuhr9384hf; Max-Age=3; Expires=' + expires.toUTCString() + '; Secure; HttpOnly; SameSite=Strict; Domain=example.com; Path=/');
        });

        it('formats a header with server definition (base64)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('sid', { encoding: 'base64' });
            const header = await definitions.format({ name: 'sid', value: 'fihfieuhr9384hf' });
            expect(header[0]).to.equal('sid=ZmloZmlldWhyOTM4NGhm; Secure; HttpOnly; SameSite=Strict');
        });

        it('formats a header with server definition (base64json)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('sid', { encoding: 'base64json' });
            const header = await definitions.format({ name: 'sid', value: { a: 1, b: 2, c: 3 } });
            expect(header[0]).to.equal('sid=eyJhIjoxLCJiIjoyLCJjIjozfQ==; Secure; HttpOnly; SameSite=Strict');
        });

        it('fails on a header with server definition and bad value (base64json)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('sid', { encoding: 'base64json' });
            const bad = { a: {} };
            bad.b = bad.a;
            bad.a.x = bad.b;

            await expect(definitions.format({ name: 'sid', value: bad })).to.reject();
        });

        it('formats a header with server definition (form)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('sid', {
                encoding: 'form',
                isSecure: false,
                isHttpOnly: false,
                isSameSite: false
            });

            const header = await definitions.format({ name: 'sid', value: { a: 1, b: 2, c: '3 x' } });
            expect(header[0]).to.equal('sid=a=1&b=2&c=3%20x');
        });

        it('formats a header with server definition (form+sign)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('sid', {
                encoding: 'form',
                isSameSite: false,
                isSecure: false,
                isHttpOnly: false,
                sign: {
                    password,
                    integrity: {
                        saltBits: 256,
                        algorithm: 'sha256',
                        iterations: 1,
                        salt: '2d75635d74c1a987f84f3ee7f3113b9a2ff71f89d6692b1089f19d5d11d140f8'
                    }
                }
            });
            const header = await definitions.format({ name: 'sid', value: { a: 1, b: 2, c: '3 x' } });
            expect(header[0]).to.equal('sid=a=1&b=2&c=3%20x.2d75635d74c1a987f84f3ee7f3113b9a2ff71f89d6692b1089f19d5d11d140f8*anm-37hjjRC3eY7Mcv4gP7gXgXBKTtUz9fNFWnetEZo');
        });

        it('formats a header with server definition (form+sign, buffer password)', async () => {

            const buffer = Buffer.from('fa4321e8c21b44a49d382fa7709226855f40eb23a32b2f642c3fd797c958718e', 'base64');
            const definitions = new Statehood.Definitions();
            definitions.add('sid', {
                encoding: 'form',
                isSameSite: false,
                isSecure: false,
                isHttpOnly: false,
                sign: {
                    password: buffer,
                    integrity: {
                        saltBits: 256,
                        algorithm: 'sha256',
                        iterations: 1,
                        salt: '2d75635d74c1a987f84f3ee7f3113b9a2ff71f89d6692b1089f19d5d11d140f8'
                    }
                }
            });
            const header = await definitions.format({ name: 'sid', value: { a: 1, b: 2, c: '3 x' } });
            expect(header[0]).to.equal('sid=a=1&b=2&c=3%20x.*4wjD4tIxyiNW-rC3xBqL56TxUbb_aQT5PMykruWlR0Q');
        });

        it('fails a header with bad server definition (form+sign)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('sid', {
                encoding: 'form',
                sign: {}
            });

            const err = await expect(definitions.format({ name: 'sid', value: { a: 1, b: 2, c: '3 x' } })).to.reject();
            expect(err.message).to.equal('Failed to encode cookie (sid) value: Empty password');
        });

        it('formats a header with server definition (iron)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('sid', { encoding: 'iron', password });
            const header = await definitions.format({ name: 'sid', value: { a: 1, b: 2, c: 3 } });
            expect(header[0]).to.have.string('sid=Fe26.2*');
        });

        it('formats a header with server definition (iron + options)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('sid', { encoding: 'iron', password, iron: Iron.defaults });
            const header = await definitions.format({ name: 'sid', value: { a: 1, b: 2, c: 3 } });
            expect(header[0]).to.have.string('sid=Fe26.2*');
        });

        it('formats a header with server definition (iron + options, buffer password)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('sid', { encoding: 'iron', password: Cryptiles.randomBits(256), iron: Iron.defaults });
            const header = await definitions.format({ name: 'sid', value: { a: 1, b: 2, c: 3 } });
            expect(header[0]).to.have.string('sid=Fe26.2*');
        });

        it('fails a header with bad server definition (iron)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('sid', { encoding: 'iron' });
            const err = await expect(definitions.format({ name: 'sid', value: { a: 1, b: 2, c: 3 } })).to.reject();
            expect(err.message).to.equal('Failed to encode cookie (sid) value: Empty password');
        });

        it('formats a header with multiple cookies', async () => {

            const definitions = new Statehood.Definitions();
            const header = await definitions.format([
                { name: 'sid', value: 'fihfieuhr9384hf', options: { ttl: 3600, path: '/', domain: 'example.com' } },
                { name: 'pid', value: 'xyz' }
            ]);

            const expires = new Date(Date.now() + 3600);
            expect(header[0]).to.equal('sid=fihfieuhr9384hf; Max-Age=3; Expires=' + expires.toUTCString() + '; Secure; HttpOnly; SameSite=Strict; Domain=example.com; Path=/');
            expect(header[1]).to.equal('pid=xyz; Secure; HttpOnly; SameSite=Strict');
        });

        it('fails on bad cookie name', async () => {

            const definitions = new Statehood.Definitions();
            const err = await expect(definitions.format({ name: 's;id', value: 'fihfieuhr9384hf', options: { isHttpOnly: false, path: '/', domain: 'example.com' } })).to.reject();
            expect(err.message).to.equal('Invalid cookie name: s;id');
        });

        it('allows bad cookie name in loose mode', async () => {

            const definitions = new Statehood.Definitions({ strictHeader: false });
            const header = await definitions.format({ name: 's;id', value: 'fihfieuhr9384hf', options: { isHttpOnly: false, path: '/', domain: 'example.com' } });
            expect(header[0]).to.equal('s;id=fihfieuhr9384hf; Secure; SameSite=Strict; Domain=example.com; Path=/');
        });

        it('allows empty cookie name in loose mode', async () => {

            const definitions = new Statehood.Definitions({ strictHeader: false });
            const header = await definitions.format({ name: '', value: 'fihfieuhr9384hf', options: { isHttpOnly: false, path: '/', domain: 'example.com' } });
            expect(header[0]).to.equal('=fihfieuhr9384hf; Secure; SameSite=Strict; Domain=example.com; Path=/');
        });

        it('allows bad cookie name in loose mode (cookie level)', async () => {

            const definitions = new Statehood.Definitions();
            definitions.add('s;id', { strictHeader: false });
            const header = await definitions.format({ name: 's;id', value: 'fihfieuhr9384hf', options: { isHttpOnly: false, path: '/', domain: 'example.com' } });
            expect(header[0]).to.equal('s;id=fihfieuhr9384hf; Secure; SameSite=Strict; Domain=example.com; Path=/');
        });

        it('fails on bad cookie value', async () => {

            const definitions = new Statehood.Definitions();
            const err = await expect(definitions.format({ name: 'sid', value: 'fi"hfieuhr9384hf', options: { isHttpOnly: false, path: '/', domain: 'example.com' } })).to.reject();
            expect(err.message).to.equal('Invalid cookie value: fi"hfieuhr9384hf');
        });

        it('fails on bad cookie value (non string)', async () => {

            const definitions = new Statehood.Definitions();
            const err = await expect(definitions.format({ name: 'sid', value: {}, options: { isHttpOnly: false, path: '/', domain: 'example.com' } })).to.reject();
            expect(err.message).to.equal('Invalid cookie value: [object Object]');
        });

        it('allows bad cookie value in loose mode', async () => {

            const definitions = new Statehood.Definitions({ strictHeader: false });
            const header = await definitions.format({ name: 'sid', value: 'fi"hfieuhr9384hf', options: { isHttpOnly: false, path: '/', domain: 'example.com' } });
            expect(header[0]).to.equal('sid=fi"hfieuhr9384hf; Secure; SameSite=Strict; Domain=example.com; Path=/');
        });

        it('fails on bad cookie domain', async () => {

            const definitions = new Statehood.Definitions();
            await expect(definitions.format({ name: 'sid', value: 'fihfieuhr9384hf', options: { isHttpOnly: false, path: '/', domain: '-example.com' } })).to.reject('Invalid cookie domain: -example.com');
        });

        it('fails on too long cookie domain', async () => {

            const definitions = new Statehood.Definitions();
            await expect(definitions.format({ name: 'sid', value: 'fihfieuhr9384hf', options: { isHttpOnly: false, path: '/', domain: '1234567890123456789012345678901234567890123456789012345678901234567890.example.com' } })).to.reject('Cookie domain too long: 1234567890123456789012345678901234567890123456789012345678901234567890.example.com');
        });

        it('formats a header with cookie domain with . prefix', async () => {

            const definitions = new Statehood.Definitions();
            const header = await definitions.format({ name: 'sid', value: 'fihfieuhr9384hf', options: { isHttpOnly: false, path: '/', domain: '.12345678901234567890.example.com' } });
            expect(header).to.equal(['sid=fihfieuhr9384hf; Secure; SameSite=Strict; Domain=.12345678901234567890.example.com; Path=/']);
        });

        it('fails on bad cookie path', async () => {

            const definitions = new Statehood.Definitions();
            await expect(definitions.format({ name: 'sid', value: 'fihfieuhr9384hf', options: { isHttpOnly: false, path: 'd', domain: 'example.com' } })).to.reject('Invalid cookie path: d');
        });
    });

    describe('passThrough()', () => {

        it('returns header unchanged', () => {

            const definitions = new Statehood.Definitions();
            const header = 'a=4;b=5;c=6';
            const result = definitions.passThrough(header);
            expect(result).to.equal(header);
        });

        it('returns header excluding local', () => {

            const definitions = new Statehood.Definitions();
            definitions.add('b');
            const header = 'a=4;b=5;c=6';
            const result = definitions.passThrough(header);
            expect(result).to.equal('a=4;c=6');
        });

        it('returns header including local (fallback)', () => {

            const definitions = new Statehood.Definitions();
            definitions.add('b');
            const header = 'a=4;b=5;c=6';
            const result = definitions.passThrough(header, true);
            expect(result).to.equal('a=4;b=5;c=6');
        });

        it('returns header including local (state option)', () => {

            const definitions = new Statehood.Definitions();
            definitions.add('b', { passThrough: true });
            const header = 'a=4;b=5;c=6';
            const result = definitions.passThrough(header);
            expect(result).to.equal('a=4;b=5;c=6');
        });

        it('returns header including local (state option with fallback)', () => {

            const definitions = new Statehood.Definitions();
            definitions.add('b', { passThrough: false });
            const header = 'a=4;b=5;c=6';
            const result = definitions.passThrough(header, true);
            expect(result).to.equal('a=4;c=6');
        });

        it('errors on invalid header', () => {

            const definitions = new Statehood.Definitions();
            definitions.add('b');
            const header = 'a=4;b=5;c=6;;';
            const result = definitions.passThrough(header);
            expect(result.message).to.equal('Invalid cookie header');
        });
    });
});

describe('prepareValue()', () => {

    it('throws when missing options', async () => {

        await expect(Statehood.prepareValue('name', 'value')).to.reject('Missing or invalid options');
    });
});

describe('exclude()', () => {

    it('returns all keys', () => {

        const header = 'a=4;b=5;c=6';
        const result = Statehood.exclude(header, []);
        expect(result).to.equal(header);
    });

    it('returns keys without excluded', () => {

        const header = 'a=4;b=5;c=6';
        const result = Statehood.exclude(header, ['b']);
        expect(result).to.equal('a=4;c=6');
    });

    it('returns keys without excluded (empty name)', () => {

        const header = '=4;b=5;c=6';
        const result = Statehood.exclude(header, ['']);
        expect(result).to.equal('b=5;c=6');
    });

    it('returns error on invalid header', () => {

        const header = 'a';
        const result = Statehood.exclude(header, ['b']);
        expect(result.message).to.equal('Invalid cookie header');
    });
});
