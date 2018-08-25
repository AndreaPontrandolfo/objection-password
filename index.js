'use strict';

const Upash = require('upash');

// Install the algorithm of your choice.
Upash.install('argon2', require('@phc/argon2'));

module.exports = (options) => {

    // Provide good defaults for the options if possible.
    options = Object.assign({
        allowEmptyPassword: false,
        passwordField: 'password'
    }, options);

    // Return the mixin. If your plugin doesn't take options, you can simply export
    // the mixin. The factory function is not needed.
    return (Model) => {

        return class extends Model {

            $beforeInsert(context) {

                const maybePromise = super.$beforeInsert(context);

                return Promise.resolve(maybePromise).then(() => {
                    // hash the password
                    return this.generateHash();
                });
            }

            $beforeUpdate(queryOptions, context) {

                const maybePromise = super.$beforeUpdate(queryOptions, context);

                return Promise.resolve(maybePromise).then(() => {
                    if (queryOptions.patch && this[options.passwordField] === undefined) {
                        return;
                    }

                    // hash the password
                    return this.generateHash();
                });
            }

            /**
             * Compares a password to a argon2 hash
             * @param  {String}             password  the password...
             * @return {Promise.<Boolean>}            whether or not the password was verified
             */
            verifyPassword(password) {
                return Upash.verify(password, this[options.passwordField]);
            }

            /**
             * Generates a argon2 hash
             * @return {Promise.<(String|void)>}  returns the hash or null
             */
            generateHash() {

                const password = this[options.passwordField];

                if (password) {
                    return Upash.hash(password)
                        .then((hash) => {
                            this[options.passwordField] = hash;
                        });
                }

                // throw an error if empty passwords aren't allowed
                if (!options.allowEmptyPassword) {
                    throw new Error('password must not be empty');
                }

                return Promise.resolve();
            }
        };

    };
};
