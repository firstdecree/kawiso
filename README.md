<div align="center"><img src="./public/assets/img/favicon.png" width="155" height="155"></div>

# Kawiso
Kawiso is a powerful, lightweight, and intuitive analytics platform. Gain actionable insights without compromising user privacy. Fully open-source and First Decree compliant.

# ⚙️ Installations
## Github
```
git clone https://github.com/firstdecree/kawiso
```

## NpmJS
```
npm install
```

## PNPM
```
pnpm install
```

# 🛠️ Setup
In order to run Kawiso, it is first necessary to configure it by making adjustments to the `example.config.toml` (remove the `example.` part in the name afterwards) file. All of the necessary descriptions for each variable are already included.

# 📦 Deployment
To deploy Kawiso, first create a [Vercel](https://vercel.com/) account. Then, install Vercel with the command `npm i vercel -g` and run the command `vercel --prod`. It's done! You can now use it on your websites.

# 🚀 Usage
```
node index.js
```

# 🔐 Security & Privacy
## Login
- **hashedUsername:** A SHA-512 hash of the username. This field is required for user lookup. Since AES-256 encryption is randomized, it is not possible to reliably identify a user using the encrypted username alone.
- **username:** The username encrypted using AES-256.
- **password:** The password hashed using SHA-512.

The cookie is also encrypted using **aes-256-gcm**.

## Analytics
- No IP addresses are logged.
- As much as possible all logged data is generalized to ensure it can't be traced back to the user.
- Only the minimal amount of data necessary for Kawiso to effectively convey website statistics to the user is logged.

# 🌐 Social Network
- **Product Hunt:** https://www.producthunt.com/products/kawiso

# 🌟 Backers & Sponsors
<table border="1">
    <tr>
        <td style="text-align: center; padding: 10px;">
            <img src="https://i.ibb.co/W46hXD5f/download.png" alt="Vexhub Hosting" style="width: 150px; height: auto; border-radius:50%; object-fit:cover;">
            <br>
            <p align="center"><a href="https://vexhub.dev/">Vexhub Hosting</a></p>
        </td>
        <td style="text-align: center; padding: 10px;">
            <img src="https://i.ibb.co/1fvHmWM3/apple-touch-icon-256x256.png" alt="Vercel" style="width: 150px; height: auto; border-radius:50%; object-fit:cover;">
            <br>
            <p align="center"><a href="https://vercel.com/">Vercel</a></p>
        </td>
    </tr>
</table>

<div align="center">
  <sub>This project is distributed under <a href="/LICENSE"><b>MIT License</b></a></sub>
</div>