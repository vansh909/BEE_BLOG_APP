const express = require("express");
const app = express();
const port = 3000;
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const validator = require("validator");
const { error, log } = require("console");
const userFilePath = path.join(__dirname, "./users.json");
const blogFile = path.join(__dirname, "./blogs.json");
const followFile = path.join(__dirname, "./userAccount.json");
const secret_key = "supersecretkey"; // Single secret key for both users and admins

app.use(express.json());
app.use(cookieParser());

app.listen(port, (err) => {
    if (err) console.log(error);
    console.log(`server is listening on ${port}`);
});
// Read and write functions for users and blogs
const readUsers = () => {
    const data = fs.readFileSync(userFilePath, "utf-8");
    return data.trim() === "" ? [] : JSON.parse(data);
};

const createUser = (data) => {
    fs.writeFileSync(userFilePath, JSON.stringify(data, null, 2), "utf-8");
};

const readFollower = () => {
    const data = fs.readFileSync(followFile, "utf-8");
    return data.trim() === "" ? [] : JSON.parse(data);
};

const writeToFollowFile = (data) => {
    fs.writeFileSync(followFile, JSON.stringify(data, null, 2), "utf-8");
};

const readBlogs = () => {
    const data = fs.readFileSync(blogFile, "utf-8");
    return data.trim() === "" ? [] : JSON.parse(data);
};

const createBlog = (data) => {
    fs.writeFileSync(blogFile, JSON.stringify(data, null, 2), "utf-8");
};

app.post("/signup", (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !password || !email) {
        return res.status(400).send("All fields are mandatory");
    }
    if (!validator.isEmail(email)) {
        return res.status(400).send("Please enter a valid email address");
    }
    if (password.length < 5) {
        return res.status(400).send("Password should be longer");
    }

    const users = readUsers();
    const userExist = users.find((a) => a.email === email);
    if (userExist) {
        return res.status(400).send("User with the same email already exists");
    }

    bcrypt.genSalt(10, (err, salt) => {
        if (err) return console.log(err);
        bcrypt.hash(password, salt, (err, hash) => {
            if (err) return console.log(err);
            if (users.length === 0) {
                // No admins exist yet, so the first user will be the admin
                const adminUser = {
                    id: users.length > 0 ? users[users.length - 1].id + 1 : 1,
                    username,
                    email,
                    password: hash,
                    role: "admin",
                    isAdmin: true,
                    // followers: [],
                    // followerCount: 0,
                    isPrivate: true,
                    // requests: [],
                };
                users.push(adminUser);
                createUser(users);

                const followers = readFollower();
                const newFollowObj = {
                    id:
                        followers.length > 0
                            ? followers[followers.length - 1].id + 1
                            : 1,
                    userId: adminUser.id,
                    user: username,
                    RequestsSent: [],
                    RequestsRecieved: [],
                    followers: [],
                    followersCount: 0,
                    isPrivate: adminUser.isPrivate,
                    requestStatus: "No Requests",
                };
                followers.push(newFollowObj);
                writeToFollowFile(followers);
                // Create admin token
                const admintoken = jwt.sign(
                    { id: adminUser.id, role: "admin" },
                    secret_key,
                    { expiresIn: "1h" }
                );
                res.cookie("token", admintoken, {
                    httpOnly: true,
                    secure: true,
                    maxAge: 3600000,
                });

                return res.status(201).json({
                    message: "Admin created successfully",
                    admin: {
                        id: adminUser.id,
                        username: adminUser.username,
                        email: adminUser.email,
                        role: adminUser.role,
                        // followers: adminUser.followers,
                        // followerCount: adminUser.followerCount,
                        isPrivate: adminUser.isPrivate,
                        // requests: adminUser.requests,
                    },
                });
            } else {
                // All other users will be regular users
                const newUser = {
                    id: users.length > 0 ? users[users.length - 1].id + 1 : 1,
                    username,
                    email,
                    password: hash,
                    role: "user",
                    isAdmin: false,
                    // followers: [],
                    // followerCount: 0,
                    isPrivate: false,
                    // requests: [],
                };
                users.push(newUser);
                createUser(users);
                const followers = readFollower();
                const newFollowObj = {
                    id:
                        followers.length > 0
                            ? followers[followers.length - 1].id + 1
                            : 1,
                    userId: newUser.id,
                    user: username,
                    RequestsSent: [],
                    RequestsRecieved: [],
                    followers: [],
                    followersCount: 0,
                    isPrivate: newUser.isPrivate,
                    requestStatus: "No Requests",
                };
                followers.push(newFollowObj);
                writeToFollowFile(followers);

                return res.status(201).json({
                    message: "User created successfully",
                    user: {
                        id: newUser.id,
                        username: newUser.username,
                        email: newUser.email,
                        role: newUser.role,
                        // followers: newUser.followers,
                        // followerCount: newUser.followerCount,
                        isPrivate: newUser.isPrivate,
                    },
                });
            }
        });
    });
});

// Login route (for both users and admins)
app.post("/login", (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
        return res.status(400).send("All fields are mandatory");

    const users = readUsers();
    const user = users.find((user) => user.email === email);
    if (!user) return res.status(400).send("User doesn't exist");

    bcrypt.compare(password, user.password, (err, result) => {
        if (err) return console.log(err);
        if (!result) return res.status(400).send("Invalid password");

        const token = jwt.sign(
            { id: user.id, isAdmin: user.isAdmin },
            secret_key,
            { expiresIn: "1h" }
        );
        res.cookie("token", token, {
            httpOnly: true,
            secure: true,
            maxAge: 3600000,
        });

        return res.status(200).json({
            message: `${user.isAdmin ? "Admin" : "User"} login successful`,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
            },
        });
    });
});

// Middleware to verify if the user is authenticated and optionally an admin
const verifyUserOrAdmin = (req, res, next) => {
    const token = req.cookies["token"];
    if (!token) return res.status(401).send("Token not provided");
    jwt.verify(token, secret_key, (err, decodedUser) => {
        if (!err) {
            const users = readUsers();
            const user = users.find((a) => a.id === decodedUser.id);
            if (user) {
                req.user = user;
                next();
            }
        }
    });
};

// Admin-only route to create another admin
app.post("/admin", verifyUserOrAdmin, (req, res) => {
    if (!req.user.isAdmin)
        return res.status(403).send("Admin privileges required");
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).send("All fields are mandatory");
    }
    const users = readUsers();
    const userExist = users.find((user) => user.email === email);
    if (userExist) {
        return res.status(400).send("User with the same email already exists");
    }
    bcrypt.genSalt(10, (err, salt) => {
        if (err) {
            return console.log(err);
        }
        bcrypt.hash(password, salt, (err, hash) => {
            if (err) {
                return console.log(err);
            }
            // No admins exist yet, so the first user will be the admin
            const adminUser = {
                id: users.length > 0 ? users[users.length - 1].id + 1 : 1,
                username,
                email,
                password: hash,
                role: "admin",
                isAdmin: true,
                // followers: [],
                // followerCount: 0,
                isPrivate: true,
                requestStatus: "No Requests",
            };
            users.push(adminUser);
            createUser(users);

            const followers = readFollower();
            const newFollowObj = {
                id:
                    followers.length > 0
                        ? followers[followers.length - 1].id + 1
                        : 1,
                userId: adminUser.id,
                user: username,
                RequestsSent: [],
                RequestsRecieved: [],
                followers: [],
                followersCount: 0,
                isPrivate: adminUser.isPrivate,
            };
            followers.push(newFollowObj);
            writeToFollowFile(followers);

            return res.status(201).json({
                message: "Admin created successfully",
                admin: {
                    id: adminUser.id,
                    username: adminUser.username,
                    email: adminUser.email,
                    role: adminUser.role,
                    isPrivate: adminUser.isPrivate,
                    // followers: adminUser.followers,
                    // followerCount: adminUser.followerCount,
                },
            });
        });
    });
});

app.get("/users", verifyUserOrAdmin, (req, res) => {
    const users = readUsers();
    return res.status(200).json(users);
});

app.get("/current", verifyUserOrAdmin, (req, res) => {
    const { id, username, role } = req.user;
    res.status(200).json({
        message: `Welcome ${role} `,
        userId: id,
        username: username,
    });
});

app.post("/blogs", verifyUserOrAdmin, (req, res) => {
    const { title, desc } = req.body;
    if (!title || !desc) {
        res.status(400).send("all fields are mandatory");
    }

    const { username, id } = req.user;
    const blogs = readBlogs();
    const newBlog = {
        id: blogs.length > 0 ? blogs[blogs.length - 1].id + 1 : 1,
        author: username,
        title,
        desc,
        authorId: id,
        likes: [],
        likesCount: 0,
    };
    blogs.push(newBlog);
    createBlog(blogs);
    return res
        .status(201)
        .json({ message: "Blog created successfully", blog: newBlog });
});

app.put("/blogs/:blogId", verifyUserOrAdmin, (req, res) => {
    const blogs = readBlogs();
    const { blogId } = req.params;
    console.log(blogId);
    const { title, desc } = req.body;
    const { username, id } = req.user;
    if (!title || !desc) {
        return res.status(400).send("All Fields are mandatory");
    }
    const blog = blogs.find((a) => a.id == blogId);
    console.log(blog);
    if (blog) {
        console.log(username);
        console.log(blog);
        if (blog.authorId == id) {
            (blog.title = title), (blog.desc = desc);
            createBlog(blogs);
            return res
                .status(201)
                .json({ message: "Blog updated successfully", Blog: blog });
        }
        return res.status(400).send("You cannot edit this blog");
    }
    return res.status(401).send("Blog not found");
});

app.delete("/blogs/:id", verifyUserOrAdmin, (req, res) => {
    const blogs = readBlogs();
    const { id } = req.params;
    const user = req.user;
    const idx = blogs.findIndex((a) => a.id == id);
    const blog = blogs[idx];
    if (!blog) {
        return res.status(400).send("Blog not found");
    }
    if (user.role == "admin" || blog.authorId == user.id) {
        blogs.splice(idx, 1);
        blogs.forEach((element, idx) => {
            element.id = idx + 1;
        });
        createBlog(blogs);
        return res.status(201).json("Blog deleted successfully");
    }
    return res.status(400).send("You cannot delete this blog!");
});

app.post("/blogs/:blogId/likes", verifyUserOrAdmin, (req, res) => {
    const blogId = req.params.blogId;
    const { username } = req.user;
    let blogs = readBlogs();
    let idx = blogs.findIndex((blog) => blog.id === parseInt(blogId));

    if (idx === -1) {
        return res.status(400).send("Blog doesn't exist!");
    }

    let likesIndex = blogs[idx].likes.indexOf(username);

    if (likesIndex === -1) {
        // Liking the blog
        blogs[idx].likes.push(username);
    } else {
        // Unliking the blog
        blogs[idx].likes.splice(likesIndex, 1);
    }

    // Update likesCount based on the likes array
    blogs[idx].likesCount = blogs[idx].likes.length;
    createBlog(blogs); // Save the updated blogs list

    const action = likesIndex === -1 ? "liked" : "unliked";
    return res.status(200).json(`Blog ${action} successfully!`);
});

app.get("/blogs", verifyUserOrAdmin, (req, res) => {
    const blogs = readBlogs();
    return res.status(200).json(blogs);
});



app.post("/follow/send-request", verifyUserOrAdmin, (req, res) => {
    const { followeeId } = req.body;
    const user = req.user;
    if (!followeeId || typeof followeeId != "number") {
        return res.status(400).send("Invalid Request");
    }
    if(followeeId == user.id)
    {
        return res.status(400).send("You cannot follow yourself!")
    }
    const followersFile = readFollower();
    const followee = followersFile.find((a) => a.userId == followeeId);
    if (!followee) {
        return res.status(400).send("Followee Not found!");
    }
    if (followee.followers.includes(user.username)) {
        return res.status(400).send("Already following this user.");
    }

    // console.log(user);
    const follower = followersFile.find((a) => a.userId == user.id);
    if (followee.isPrivate) {
        followee.RequestsRecieved.push(user.username);
        followee.requestStatus = "Pending";
        follower.RequestsSent.push(followee.user);
        writeToFollowFile(followersFile);
        return res.status(200).json(`Request sent!`);
    } else {
        follower.RequestsSent.push(followee.user);
        followee.followers.push(user.username);
        followee.followersCount = followee.followers.length;
        writeToFollowFile(followersFile);
        return res.status(200).json("Followed account");
    }
});

app.post("/follow/accept-request", verifyUserOrAdmin, (req, res) => {
    const { accepted } = req.body;
    if (!accepted) {
        return res.status(400).send("Invalid Request!");
    }
    const user = req.user;
    const userId = user.id;
    const followersFile = readFollower();
    const follower = followersFile.find((a) => a.userId == userId);
    if (follower.RequestsRecieved.length==0) {
        return res.status(400).send("No Incoming request");
    }
    if (accepted == "yes") {
        for (i = 0; i < follower.RequestsRecieved.length; i++) {
            // follower.followers = follower.RequestsRecieved[i];
            follower.followers.push(follower.RequestsRecieved[i])
            follower.followersCount++;
        }
        follower.RequestsRecieved = [];
        follower.requestStatus = "No Requests!";
        writeToFollowFile(followersFile);
        return res
            .status(200)
            .json({ message: "All Request Accepted!", userDetails: follower });
    }
    else if (accepted=="no"){
        follower.RequestsRecieved = [];
        follower.requestStatus = "No Requests";
        writeToFollowFile(followersFile);
        return res
            .status(200)
            .json({message: "All Requests Denied!", userDetails: follower});
    }
    else
    {
        return res
            .status(400)
            .send("Invalid Request!")
    }
});
