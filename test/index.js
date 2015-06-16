var mongoose = require("mongoose");
var mockgoose = require("mockgoose");
var server = require(__dirname + "/../../../lib/server");
var model = require(__dirname + "/../index").model();
var tokenModel = require(__dirname + "/../index").tokenModel();
var hawk = require("hawk");
var passportLocalMongoose = require("passport-local-mongoose");
var fs = require("fs");
var hat = require("hat");
var _ = require("lodash");
var uuid = require("uuid");
var moment = require("moment");

var User = mongoose.model("User");
var Profile = mongoose.model("User");

require("must");
var async = require("async");

var hawkPairKey = {
  algorithm : "sha256"
}
var expiredPairKey = {
  id : uuid.v4(),
  key : uuid.v4(),
  algorithm : "sha256"
}

var port = "3000";
if (process.env.PORT) port = process.env.PORT;
var prefix = "http://localhost:" + port;

describe("User", function() {
  this.timeout(50000);
  before(function(done){
    User.remove(function(err){
      if (err) done(err);
      var users;
      fs.readFile(__dirname + "/users.json", "utf8", function(err, data) {
        if (err) done(err);
        users = JSON.parse(data);
        async.each(users, function(user, cb) {
          var newUser = new User(user);
          newUser.save(function(err){
            if (err) done(err);
            cb()
          })
        }, function(err) {
          if (err) done(err);
          done();
        });
      });
    });
  })
  describe("User auth", function() {
    this.timeout(50000);
    it("should logged in and get hawk pair key from /api/users/login", function(done) {
      server.inject({
        method: "POST",
        url: "/api/users/login",
        payload : {
          email : "auth1@users.com",
          password : "pass1"
        },
      }, function(response) {
        response.result.must.be.an.object();
        response.result.success.must.equal(true);
        response.headers.token.must.be.exist();
        hawkPairKey.id = response.headers.token.split(" ")[0];
        hawkPairKey.key = response.headers.token.split(" ")[1];
        done();
      });
    });
    it("should failed to login with invalid credentials from /api/users/login", function(done) {
      server.inject({
        method: "POST",
        url: "/api/users/login",
        payload : {
          username : "auth1@users.com",
          password : "wrongPassword"
        },
      }, function(response) {
        response.result.must.be.an.object();
        response.result.error.must.exist();
        response.result.message.must.exist();
        response.result.statusCode.must.exist();
        response.result.error.must.equal("Unauthorized");
        response.result.message.must.equal("Unknown credentials");
        response.result.statusCode.must.equal(401);
        done();
      });
    });
    it("should failed to login with non active user from /api/users/login", function(done) {
      server.inject({
        method: "POST",
        url: "/api/users/login",
        payload : {
          email : "auth3@users.com",
          password : "pass1"
        },
      }, function(response) {
        response.result.must.be.an.object();
        response.result.error.must.exist();
        response.result.message.must.exist();
        response.result.statusCode.must.exist();
        response.result.error.must.equal("Unauthorized");
        response.result.message.must.equal("Not active");
        response.result.statusCode.must.equal(401);
        done();
      });
    });
    it("should logged out by query /api/users/logout", function(done) {
      var path = "/api/users/logout";
      var header = hawk.client.header(prefix + path, "GET", { credentials : hawkPairKey });
      server.inject({
        headers : { Authorization : header.field, host : "localhost:3000" },
        url: path,
        method: "GET",
      }, function(response) {
        response.result.must.be.an.object();
        response.result.success.must.equal(true);
        done();
      });
    });
    it("should logged out with invalid credentials by query /api/users/logout", function(done) {
      var path = "/api/users/logout";
      var header = hawk.client.header(prefix + path, "GET", { credentials : hawkPairKey });
      server.inject({
        headers : { Authorization : header.field, host : "localhost:3000" },
        url: path,
        method: "GET",
      }, function(response) {
        response.result.must.be.an.object();
        response.result.error.must.exist();
        response.result.message.must.exist();
        response.result.statusCode.must.exist();
        response.result.error.must.equal("Unauthorized");
        response.result.message.must.equal("Unknown credentials");
        response.result.statusCode.must.equal(401);
        done();
      });
    });
    it("should failed to logout with expired pair key /api/users/logout", function(done) {
      server.inject({
        method: "POST",
        url: "/api/users/login",
        payload : {
          email : "auth2@users.com",
          password : "pass1"
        },
      }, function(response) {
        response.result.must.be.an.object();
        response.result.success.must.equal(true);
        response.headers.token.must.be.exist();
        expiredPairKey.id = response.headers.token.split(" ")[0];
        expiredPairKey.key = response.headers.token.split(" ")[1];
        tokenModel.findOne({
          tokenId : expiredPairKey.id,
        }, function(err, result){
          if (err) return done(err);
          result.expire = moment().subtract(1, "day").format();
          result.save(function(err){
            var path = "/api/users/logout";
            var header = hawk.client.header(prefix + path, "GET", { credentials : expiredPairKey });
            server.inject({
              headers : { Authorization : header.field, host : "localhost:3000" },
              url: path,
              method: "GET",
            }, function(response) {
              response.result.must.be.an.object();
              response.result.error.must.exist();
              response.result.message.must.exist();
              response.result.statusCode.must.exist();
              response.result.error.must.equal("Unauthorized");
              response.result.message.must.equal("Expired token");
              response.result.statusCode.must.equal(401);
              done();
            });
          });
        });
      });
    });
    it("should failed to logout (or perform a hawk auth) with non active user/api/users/logout", function(done) {
      server.inject({
        method: "POST",
        url: "/api/users/login",
        payload : {
          email : "auth4@users.com",
          password : "pass1"
        },
      }, function(response) {
        response.result.must.be.an.object();
        response.result.success.must.equal(true);
        response.headers.token.must.be.exist();
        expiredPairKey.id = response.headers.token.split(" ")[0];
        expiredPairKey.key = response.headers.token.split(" ")[1];
        User.findOne({
          username : "auth4@users.com",
        }, function(err, result){
          if (err) return done(err);
          result.isActive = false;
          result.save(function(err){
            var path = "/api/users/logout";
            var header = hawk.client.header(prefix + path, "GET", { credentials : expiredPairKey });
            server.inject({
              headers : { Authorization : header.field, host : "localhost:3000" },
              url: path,
              method: "GET",
            }, function(response) {
              response.result.must.be.an.object();
              response.result.error.must.exist();
              response.result.message.must.exist();
              response.result.statusCode.must.exist();
              response.result.error.must.equal("Unauthorized");
              response.result.message.must.equal("Not active");
              response.result.statusCode.must.equal(401);
              done();
            });
          });
        });
      });
    });
  });
});
