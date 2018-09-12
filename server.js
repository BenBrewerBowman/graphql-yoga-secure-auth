const { GraphQLServer } = require('graphql-yoga');
const helmet = require('helmet');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const ms = require('ms');


const typeDefs = `
  type Query {
    isLoggedIn: Boolean!
  }
  type Mutation {
    logIn(username: String!, pwd: String!): Boolean!
    signUp(username: String!, pwd: String!): Boolean!
    logOut: Boolean!
  }
`

// mock mockDBbase
const mockDB = {};

const resolvers = {

  Query: {
    // is the user authenticated
    isLoggedIn: (parent, args, { req }) => {
      return req.session.isLoggedIn === true;
    }
  },

  Mutation: {

    // user can sign up for a new account
    signUp: async (parent, { email, pwd }, ctx) => {
      // if user is already in the DB
      if (mockDB[email]) {
        throw new Error('This user already exists, please log in.');
      }
      const saltRounds = 14; // roughly 1.5 secs on 2GHZ CPU
      // store pwd in mock DB (replace with real DB)
      mockDB[email] = {
        // salt and hash pw
        pwd: await bcrypt.hashSync(pwd, saltRounds),
      };
      return true;
    },

    // authenticates user into respective account
    logIn: async (parent, { email, pwd }, { req }) => {
      // grab user from DB
      const user = mockDB[email];
      if (user) {
        // make sure pw matches
        if (await bcrypt.compareSync(pwd, user.pwd)) {
          // set user logged in flag
          req.session.isLoggedIn = true;
          return true;
        }
        throw new Error('User email or password is incorrect.');
      }
      throw new Error('User email or password is incorrect.');
    },

    // remove user from session
    logOut: async (parent, args, { req }) => {
      await req.session.destroy();
      return true;
    },
  }
}

// opts
const opts = {
  port: 4000,
  cors: {
    credentials: true,
    origin: ['http://localhost:8080'] // your frontend url.
  }
};

// context
const context = (req) => ({
  req: req.request,
});

// server
const server = new GraphQLServer({
  typeDefs,
  resolvers,
  context,
});

// helmet middleware helps secure app by setting various HTTP headers
server.express.use(helmet());

// session middleware 
server.express.use(session({
  name: 'SSID',
  // change this to randomly generate a secret
  secret: `my-super-secret-secret`,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production',
    maxAge: ms('1d'),
  },
}));

// start server
server.start(opts, () => console.log(`Server is running on http://localhost:${opts.port}`));