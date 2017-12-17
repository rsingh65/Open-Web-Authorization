const assert = require('assert');
var bcrypt = require('bcrypt');
let axios = require('axios');

const USERS = 'users';
const DEFAULT_USERS = './users_data';
const DATA = '_data';

function Users(db) {
    this.db = db;
    this.users = db.collection(USERS);
}

Users.prototype.getUser = function (app) {
    //console.log(id);
    /*const searchSpec = {
        _id: id
    };
    return this.users.find(searchSpec).toArray().
    then(function (users) {
        return new Promise(function (resolve, reject) {
            if (users.length === 1) {
                resolve(users[0].DATA);
            } else if (users.length == 0 && !mustFind) {
                resolve(null);
            } else {
                reject(new Error(`cannot find user ${id}`));
            }
        });
    });*/
    console.log("inside user get");
    return 1;
    axios.get("https://localhost:3000/").
    then(function(response){
        console.log("Reached");
        return 0;
    });
}

Users.prototype.authUser = function (id, pw, mustFind = true) {
    //console.log("inside prototype auth users 1");
    //var hash = bcrypt.hashSync(pw, 10);
    //bcrypt.compareSync(myPlaintextPassword, hash);
    const searchSpec = {
        _id: id
    };
    console.log(searchSpec);
    return this.users.find(searchSpec).toArray().
    then(function (users) {
        return new Promise(function (resolve, reject) {
            //console.log("inside prototype auth users 2");
            //console.log(users);
            if (users.length === 1) {
                let passMatch = bcrypt.compareSync(pw, users[0].pw);
                if (passMatch) {
                    resolve(users[0].DATA);
                } else {
                    resolve(null);
                }

            } else if (users.length == 0 && !mustFind) {
                resolve(null);
            } else {
                reject(new Error(`cannot find user ${id}`));
            }
        });
    });
}

Users.prototype.newUser = function (id, pw, user) {
    var hash = bcrypt.hashSync(pw, 10);
    const d = {
        _id: id,
        pw: hash,
        DATA: user
    };
    //console.log(hash);
    return this.users.insertOne(d).
    then(function (results) {
        return new Promise((resolve) => resolve(results.insertedId));
    });
}

Users.prototype.deleteUser = function (id) {
    return this.users.deleteOne({
        _id: id
    }).
    then(function (results) {
        return new Promise(function (resolve, reject) {
            if (results.deletedCount === 1) {
                resolve();
            } else {
                reject(new Error(`cannot delete user ${id}`));
            }
        });
    });
}

Users.prototype.updateUser = function (id, pw, user) {
    const d = {
        _id: id,
        pw: pw,
        DATA: user
    };
    return this.users.replaceOne({
        _id: id
    }, d).
    then(function (result) {
        return new Promise(function (resolve, reject) {
            if (result.modifiedCount != 1) {
                reject(new Error(`updated ${result.modifiedCount} users`));
            } else {
                resolve();
            }
        });
    });
}

module.exports = {
    Users: Users
};
