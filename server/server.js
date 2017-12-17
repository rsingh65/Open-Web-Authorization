const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bearerToken = require('express-bearer-token');
const assert = require('assert');
const fs = require('fs');
const https = require('https');
const Mustache = require('mustache');
let axios = require('axios');

const OK = 200;
const CREATED = 201;
const NO_CONTENT = 204;
const MOVED_PERMANENTLY = 301;
const FOUND = 302;
const SEE_OTHER = 303;
const NOT_MODIFIED = 303;
const BAD_REQUEST = 400;
const NOT_FOUND = 404;
const CONFLICT = 409;
const SERVER_ERROR = 500;
const ERROR_UNAUTHORIZED = 401;

const secret = new Buffer("something", "base64").toString();
const templateLogin = '<label>Email : </label><input type="text" id="email" value="{{email}}"><br/><br/><label>Password : </label><input type="text" id="password" value="{{password}}"><br/><br/><input type="button" id="btnSubmit" value="Submit"><br/><a href="/registration">Register</a><script src="https://ajax.googleapis.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script><script>$("#btnSubmit").click(function(){$.ajax({type: "POST",url:"/login",processData: false,contentType: "application/json",data: JSON.stringify({"email":$("#email").val().trim(),"password":$("#password").val().trim()})})})</script>'

const registrationPage = '<label>First Name : </label><input type="text" id="firstName"><br/><br/><label>Last Name : </label><input type="text" id="lastName"><br/><br/><label>Email : </label><input type="text" id="email"><br/><br/><label>Password : </label><input type="text" id="password"><br/><br/><label>Confirm Password : </label><input type="text" id="confirmPassword"><br/><br/><input type="button" id="btnRegister" value="Register"><br/><script src="https://ajax.googleapis.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script><script>$("#btnRegister").click(function(){$.ajax({type: "POST",url:"/registerUser",processData: false,contentType: "application/json",data: JSON.stringify({"firstName":$("#firstName").val().trim(),"lastName":$("#lastName").val().trim(),"email":$("#email").val().trim(),"password":$("#password").val().trim()})})})</script>'

const account = '<label>First Name : </label><label>{{firstName}}</label><br/><br/><label>First Name : </label><label>{{lastName}}</label><br/><br/><input type="button" id="btnLogout" value="Logout"><script src="https://ajax.googleapis.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script><script>$("#btnLogout").click(function(){$.ajax({type: "GET",url:"/login",processData: false,contentType: "application/json",data: JSON.stringify({"email":$("#email").val().trim(),"password":$("#password").val().trim()})})})</script>'
let authTime;

function generateToken(req) {
    var token = jwt.sign({
        auth: 'rohit',
        agent: req.headers['user-agent'],
        iat: (new Date().getTime() / 1000),
        exp: (new Date().getTime() / 1000) + authTime
    }, secret); // secret is defined in the environment variable JWT_SECRET
    return token;
}

function serve(options, model) {
    console.log("Inside serve");
    const port = options.port;
    //console.log(options.port);
    //console.log(options.sslDir);
    //console.log(options.serUrl);
    const app = express();
    //app.locals.model = model;
    app.locals.port = port;
    app.locals.serviceurl = options.serUrl;
    setupRoutes(app);
    console.log(options.sslDir);
    console.log(options.port);
    https.createServer({
        key: fs.readFileSync(`${options.sslDir}/key.pem`),
        cert: fs.readFileSync(`${options.sslDir}/cert.pem`),
    }, app).listen(port, function () {
        console.log(`listening on port ${port}`);
    });
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
}

function setupRoutes(app) {
    console.log("Inside setuproutes");
    app.use('/users/:id', bodyParser.json());
    app.use('/users/:id', cacheUser(app));
    app.use(bearerToken());
    //app.put('/users/:id', newUser(app));
    app.get('/', loginDefault(app));
    app.use('/login', bodyParser.json());
    app.post('/login', login(app));
    app.use('/registerUser', bodyParser.json());
    app.post('/registerUser', registerUser(app));
    app.get('/registration', registerPage(app));
    //app.get('/account', accountPage(app));

    app.use('/account',bodyParser.json());
    app.get('/account', accountPage(app));

    //app.delete('/users/:id', deleteUser(app));
    //app.post('/users/:id', updateUser(app));
}

module.exports = {
    serve: serve
}

function loginDefault(app) {
    return function (request, response) {
        //check the cookie. If exits and successful login, the directly show the account page.
        /*$.cookie('email', email, {
            expires: 14
        });
        $.cookie('password', password, {
            expires: 14
        });
        $.cookie('remember', true, {
            expires: 14
        });
        var rendered = Mustache.render(templateLogin, {
            email: "",
            password: ""
        });*/
        var rendered = Mustache.render(templateLogin, {
            email: "",
            password: ""
        });
        response.status(OK).send(rendered);
        //response.status(OK).send(templateLogin);
    }
}

function login(app) {
    return function (request, response) {
        console.log("Inside login 1");
        let email = request.body.email;
        let password = request.body.password;
        console.log("email is " + email);
        console.log("password is " + password);
        axios.put("https://localhost:3000/users/" + email + "/auth", {
            "pw": password
        }).
        then(function (response) {

            //console.log(response.data.authToken);
            //onsole.log(config);
            axios.get("https://localhost:3000/users/" + email, {
                headers: {
                    Authorization: `Bearer ${response.data.authToken}`
                }
            }).
            then(function (response) {
                console.log(response.data);
                let firstName = response.data.firstName;
                let lastName = response.data.lastName;
                console.log(firstName);
                var rendered = Mustache.render(account, {
                    firstName: firstName,
                    lastName: lastName
                });
                axios.put("https://localhost:4000/account", {
                    "firstName": firstName,
                    "lastName": lastName
                }).
                then(function (result) {
                    /*console.log(response.data);
                    let firstName = result.data.firstName;
                    let lastName = result.data.lastName;
                    console.log(firstName);
                    var rendered = Mustache.render(account, {
                        firstName: firstName,
                        lastName: lastName
                    });
                    //return rendered;

                    response.status(OK).send(rendered);*/
                    console.log("1");
                    //console.log(result);
                }).catch(error => {
                    console.log("abc");

                    console.log(error);
                });
                //response.status(OK).send(rendered);

                //response.status(OK).send(templateLogin);
                console.log("Success");
            }).catch(error => {
                console.log("abc");

                console.log(error);
            });
            //response.send("Hello");
            //console.log("SuccesregisterPages");
        }).catch(error => {
            var rendered = Mustache.render(templateLogin, {
                email: email,
                password: ""
            });
            console.log(rendered);
            response.status(OK).send(rendered);
            //console.log(error);
        });
    }
}

function registerPage(app) {
    return function (request, response) {
        var rendered = Mustache.render(registrationPage, {
            email: "rohit@bu"
        });
        response.status(OK).send(rendered);
    }
}

function accountPage(app) {
    return function (request, response) {
        console.log("account page");
        let fName = request.body.firstName;
        let lName = request.body.lastName;
        console.log("body is")
        console.log(fname);
        console.log(lname);
        var rendered = Mustache.render(account, {
            firstName: request.body.firstName,
            lastName: request.body.lastName
        });
        response.status(OK).send(rendered);
    }
}

function registerUser(app) {
    return function (request, response) {
        console.log("inside register user");
        let firstName = request.body.firstName;
        let lastName = request.body.lastName;
        let email = request.body.email;
        let password = request.body.password;
        let confirmPassword = request.body.confirmPassword;

        console.log(request.body);
        /*let error = "";
        if (firstName == "") {
            error = "First name ";
        }
        if (lastName == "") {
            if (error == "") {
                error = "Last name ";
            } else {
                error += ",Last name ";
            }

        }
        if (email == "") {
            if (error == "") {
                error = "email ";
            } else {
                error += ",email ";
            }
        }
        if (password == "") {
            if (error == "") {
                error = "password ";
            } else {
                error += ",password ";
            }
        }
        if (confirmPassword == "") {
            if (error == "") {
                error = "confirm password ";
            } else {
                error += ",confirm password ";
            }
        }

        if (password != "" && confirmPassword != "") {
            if (password != confirmPassword) {
                if (error == "") {
                    error = "Passwords doesn't match ";
                } else {
                    error += ",passwords doesn't match ";
                }
            }
        }
        if (error != "") {
            error += " can't be empty"
        }*/
        //let email = document.getElementById('email').value
        //console.log(email);
        axios.put("https://localhost:3000/users/" + email + "?pw=" + password, {
            "firstName": firstName,
            "lastName": lastName,
            "email": email,
            "password": password
        }).
        then(function (response) {
            //console.log(response);
            //response.send("Hello");
            console.log("Success");
        }).catch(error => {
            console.log(error);

        });
        //response.send("Hello");

    };
}

function getUser(app) {
    return function (request, response) {
        console.log("inside get user");
        axios.put("https://localhost:3000/users/" + email + "/auth", {
            "pw": "password"
        }).
        then(function (response) {
            console.log(response);
            //response.send("Hello");
            console.log("Success");
        }).catch(error => {
            console.log(error);

        });
        //response.send("Hello");
        //request.app.locals.model.users.getUser().

        //console.log("inside get user server");        
        /*const idRec = request.params.id;
        const id = idRec;
        //console.log(idRec);
        request.app.locals.model.users.getUser(id).
        then(function (id) {
            //console.log(id);
            var encoded = request.token;
            jwt.verify(encoded, secret, function (err, decode) {
                //console.log("Decode started");
                //console.log(secret);
                if (err) {
                    console.log("Decode error");
                    console.log(err);
                    response.status(ERROR_UNAUTHORIZED).send('[{"status": "ERROR_UNAUTHORIZED","/users/":` "' + id + 'requires a bearer authorization header"}]');
                } else {
                    console.log("Decode success");
                    console.log(decode);
                    response.status(OK).send(request.user);
                }
                console.log("Decode end");
            });
        }).
        catch((err) => {
            //console.log("inside auth user server err");
            console.error(err);
            response.status(NOT_FOUND).send('[{"status": "ERROR_NOT_FOUND","info":"user ' + id + ' not found"}]');
        });*/
    };
}

function authUser(app) {
    return function (request, response) {
        //console.log("inside auth user server 1");
        const id = request.params.id;
        const pw = request.body.pw;

        console.log(pw);
        if (pw) {
            request.app.locals.model.users.authUser(id, pw).
            then(function (id) {
                //console.log(id);
                if (id) {
                    var encoded = generateToken(request);
                    response.status(OK).send('[{"status": "OK","authToken":` "' + encoded + '"}]');
                } else {
                    response.status(NOT_FOUND).send('[{"status": "ERROR_UNAUTHORIZED","info":"/users/' + id + '/auth requires a valid pw password query parameter"}]');
                }
            }).
            catch((err) => {
                //console.log("inside auth user server err");
                console.error(err);
                response.status(NOT_FOUND).send('[{"status": "ERROR_NOT_FOUND","info":"user ' + id + ' not found"}]');

            });
        } else {
            response.status(NOT_FOUND).send('[{"status": "ERROR_UNAUTHORIZED","info":"/users/' + id + '/auth requires a valid pw password query parameter"}]');
        }
    };
}

function deleteUser(app) {
    return function (request, response) {
        if (!request.user) {
            response.sendStatus(NOT_FOUND);
        } else {
            request.app.locals.model.users.deleteUser(request.params.id).
            then(() => response.sendStatus(NO_CONTENT)).
            catch((err) => {
                console.error(err);
                response.sendStatus(SERVER_ERROR);
            });
        }
    };
}

function newUser(app) {
    return function (request, response) {
        const userInfo = request.body;
        const id = request.params.id;
        var fullUrl = request.protocol + '://' + request.get('host') + request.originalUrl;

        if (typeof userInfo === 'undefined') {
            console.error(`missing body`);
            response.sendStatus(BAD_REQUEST);
        } else if (request.user) {
            response.setHeader('Location', fullUrl);
            response.status(SEE_OTHER).send('[{"status": "EXISTS","info":"user ' + id + ' already exists"}]');
        } else {
            //console.log("inside create user");
            const pw = request.query.pw;
            //console.log(userInfo);
            request.app.locals.model.users.newUser(id, pw, userInfo).
            then(function (id) {
                var encoded = generateToken(request);
                response.setHeader('Location', fullUrl);
                response.status(CREATED).send('[{"status": "CREATED","authToken":` "' + encoded + '"}]');
            }).
            catch((err) => {
                console.error(err);
                response.sendStatus(SERVER_ERROR);
            });
        }
        //response.send("Hello World put");
    };
}

function updateUser(app) {
    return function (request, response) {
        const id = request.params.id;
        const userInfo = request.body;
        if (!request.user) {
            console.error(`user ${request.params.id} not found`);
            response.sendStatus(NOT_FOUND);
        } else {
            request.app.locals.model.users.updateUser(id, userInfo).
            then(function (id) {
                response.redirect(SEE_OTHER, requestUrl(request));
            }).
            catch((err) => {
                console.error(err);
                response.sendStatus(SERVER_ERROR);
            });
        }
    };
}

function cacheUser(app) {
    return function (request, response, next) {
        const id = request.params.id;
        if (typeof id === 'undefined') {
            response.sendStatus(BAD_REQUEST);
        } else {
            request.app.locals.model.users.getUser(id, false).
            then(function (user) {
                request.user = user;
                next();
            }).
            catch((err) => {
                console.error(err);
                response.sendStatus(SERVER_ERROR);
            });
        }
    }
}

//Should not be necessary but could not get relative URLs to work
//in redirect().
function requestUrl(req) {
    const port = req.app.locals.port;
    return `${req.protocol}://${req.hostname}:${port}${req.originalUrl}`;
}
