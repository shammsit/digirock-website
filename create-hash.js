    const bcrypt = require('bcrypt');
    
    // This is the password you want to use.
    const myPassword = 'pass123';
    
    // The number of salt rounds determines how secure the hash is. 10 is a good default.
    const saltRounds = 10;
    
    console.log(`Generating a hash for the password: "${myPassword}"`);
    
    bcrypt.hash(myPassword, saltRounds, function(err, hash) {
        if (err) {
            console.error("Error generating hash:", err);
            return;
        }
        console.log("\nSUCCESS! Here is your new, correct password hash:");
        console.log("==============================================================");
        console.log(hash);
        console.log("==============================================================");
        console.log("\nPlease use this hash in your SQL UPDATE command.");
    });
    