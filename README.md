# Jethro Fork

At the moment I'm just playing around with SSO (Focused on OAuth/OIDC, but will consider SAML if there's enough interest). I trying to keep my changes as limited in scope as possible so they can eventually be rolled back into the original project. 

That said, I really, really, *really* want a full API and potetially the capacity to interact with other systems for provisioning (SCIM? Maybe something to support custom RESTful calls?). Me, personally, I want to feed a self hosted IdP like [Authentic](https://github.com/goauthentik/authentik) or [Keycloak](https://www.keycloak.org/) in support of a range of community services for my local church.

# Jethro Pastoral Ministry Manager

Jethro Pastoral Ministry Manager is a web-based tool which helps churches keep track of people, families, groups, attendance, pastoral tasks, church services, rosters and documents.  Jethro doesn't force you to work in a particular way but gives you flexible, lightweight tools to support your own style of ministry.  

The Jethro software is free and open source (GPL) and runs on a standard [LAMP](http://en.wikipedia.org/wiki/LAMP_%28software_bundle%29) web server.  Jethro's real advantages come to the fore when it's running on a proper web server, but it can also be run on a single PC using [XAMPP](XAMPP).

Jethro PMM is the software that powers online services such as [Easy Jethro](http://easyjethro.com.au) who also offer a [demo system](http://easyjethro.com.au/demo/).

# Download and install

Start with the official version [Jethro-PMM](https://github.com/tbar0970/jethro-pmm). The versions here are for experimentation and play. Please don't try and deploy my version in production. Seriously, just don't. I'd love to help, but I don't really have the time. I'm just scratching my itch... but hopefully it will eventually be able to help someone else.

# Documentation

What does the programmer say about his documentation? No comment.

# Support and Discussion

If you're having trouble with this version of Jethro, go back and read the notes under download and install. If you need to ask, you should be using [Jethro-PMM](https://github.com/tbar0970/jethro-pmm).

If you have an idea for a new feature, please [look if somebody has already requested it](https://github.com/tbar0970/jethro-pmm/issues?q=is%3Aopen+is%3Aissue+label%3Afeature-request) and if not, [open a new issue](https://github.com/tbar0970/jethro-pmm/issues/new).

# Data Model
The following is a high-level overview of the objects in Jethro and how they relate.
* A **person** has a name and various other properties.
* Every person belongs to exactly one **family**.  A family is a collection of persons who live at the same address and are in some way related.
* Every person belongs to exactly one **congregation** - the main grouping within a church.  (One exception to this is persons with status 'contact', who can be congregation-less).
* A person can belong to several **groups** which can represent many things such as bible studies, volunteers for some role, people who are undergoing a welcoming process, people who have completed some particular training course, etc etc.
* A person's **attendance** at their congregation or a certain group can be recorded week by week
* **Notes** can be added to persons or families.  These may simply record extra free-form information about the person, or may be assigned to a Jethro user for action (eg "call Mr Smith").
* A **report** can show persons who match certain rules regarding their personal details, group memberships etc etc.
* A **service** is when a congregation meets together on a certain date, and has various details such as the topic and what bible passages are to be used.
* A service's **run sheet** can contain several **service components** such as songs, prayers, etc, selected from the congregation's repertoire.
* A **roster role** is some role to be played in a service, eg reading the bible
* A **roster view** is a collection of roster roles which are viewed or edited together (eg all the roles for the evening service, or the 'preacher' roles for all services)
* A **roster assignment** is when a person is assigned to a certain roster role for a particular service.

An extensive list of Jethro's capabilities is available on the [Easy Jethro site](http://easyjethro.com.au/#features)

# Naming

Jethro is designed to facilitate and encourage good team ministry, so its name comes from Exodus 18:13-23 where Moses is introduced by his father in law to the important skill of **delegation**.  His father in law was named Jethro.

# Acknowledgements
Jethro development has been sponsored or contributed to by several churches worldwide:
* [Christ Church Inner West Anglican Community](http://cciw.org.au), Sydney, Australia (founding sponsor)
* [Redlands Presbyterian Church](http://www.redlands.org.au/), Queensland, Australia (sponsor of service planning features)
* [St Peter's Woolton](http://www.stpeters-woolton.org.uk), Liverpool, UK (sponsor of date field and photo features)
* [Coast Evangelical Church](http://www.coastec.net.au)</a>, Forster, Australia (sponsor of group-membership statuses, attendance enhancements and more)
* [St George North Anglican Church](http://snac.org.au)</a>, Sydney, Australia (contributor of vCard export)
* [Macquarie Anglican Church](http://www.macquarieanglican.org/)</a>, Sydney, Australia (contributor of note-search and SMS-family feature)
* [Dalby Presbyterian Church](http://www.dpc.cc/)</a>, Queensland, Australia (sponsor of edit/delete note features and family photos)
* [Professional Standards Unit](http://safeministry.org.au), Anglican Diocese of Sydney (sponsor of custom fields etc)
There are also several github contributors whose input is invaluable.
