pragma solidity 0.6.12;


contract EphimeraAccessControls is AccessControl {
    // Role definitions
    bytes32 public constant GALLERY_ROLE = keccak256("GALLERY_ROLE");
    bytes32 public constant CREATOR_ROLE = keccak256("CREATOR_ROLE");
    bytes32 public constant CONTRACT_WHITELIST_ROLE = keccak256(
        "CONTRACT_WHITELIST_ROLE"
    );

    // Relationship mappings
    mapping(address => mapping(address => bool)) public galleryToArtistMapping;
    mapping(address => mapping(address => bool))
        public artistToGalleriesMapping;

    // Events
    event ArtistAddedToGallery(
        address indexed gallery,
        address indexed artist,
        address indexed caller
    );

    event ArtistRemovedFromGallery(
        address indexed gallery,
        address indexed artist,
        address indexed caller
    );

    event NewAdminAdded(address indexed admin);

    event AdminRemoved(address indexed admin);

    event NewArtistAdded(address indexed artist);

    event ArtistRemoved(address indexed artist);

    event NewGalleryAdded(address indexed gallery);

    event GalleryRemoved(address indexed gallery);

    constructor() public {
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
    }

    /////////////
    // Lookups //
    /////////////

    function hasGalleryRole(address _address) public view returns (bool) {
        return hasRole(GALLERY_ROLE, _address);
    }

    function hasCreatorRole(address _address) public view returns (bool) {
        return hasRole(CREATOR_ROLE, _address);
    }

    function hasAdminRole(address _address) public view returns (bool) {
        return hasRole(DEFAULT_ADMIN_ROLE, _address);
    }

    function hasContractWhitelistRole(address _address)
        public
        view
        returns (bool)
    {
        return hasRole(CONTRACT_WHITELIST_ROLE, _address);
    }

    function isArtistPartOfGallery(address _gallery, address _artist)
        public
        view
        returns (bool)
    {
        return galleryToArtistMapping[_gallery][_artist];
    }

    ///////////////
    // Modifiers //
    ///////////////

    modifier onlyAdminRole() {
        require(
            hasRole(DEFAULT_ADMIN_ROLE, _msgSender()),
            "EphimeraAccessControls: sender must be an admin"
        );
        _;
    }

    function addAdminRole(address _address) public onlyAdminRole {
        require(
            !hasAdminRole(_address),
            "EphimeraAccessControls: Account already has an admin role"
        );
        _grantRole(DEFAULT_ADMIN_ROLE, _address);
        emit NewAdminAdded(_address);
    }

    function removeAdminRole(address _address) public onlyAdminRole {
        require(
            hasAdminRole(_address),
            "EphimeraAccessControls: Account is not an admin"
        );
        _revokeRole(DEFAULT_ADMIN_ROLE, _address);
        emit AdminRemoved(_address);
    }

    function addContractWhitelistRole(address _address) public onlyAdminRole {
        require(
            !hasContractWhitelistRole(_address),
            "EphimeraAccessControls: Address has contractWhitelist role"
        );
        _grantRole(CONTRACT_WHITELIST_ROLE, _address);
    }

    function removeContractWhitelistRole(address _address)
        public
        onlyAdminRole
    {
        require(
            hasContractWhitelistRole(_address),
            "EphimeraAccessControls: Address must have contractWhitelist role"
        );
        _revokeRole(CONTRACT_WHITELIST_ROLE, _address);
    }

    function addGalleryRole(address _address) public onlyAdminRole {
        require(
            !hasCreatorRole(_address),
            "EphimeraAccessControls: Address already has creator role and cannot have gallery role at the same time"
        );
        require(
            !hasGalleryRole(_address),
            "EphimeraAccessControls: Address already has gallery role"
        );

        _grantRole(GALLERY_ROLE, _address);
        emit NewGalleryAdded(_address);
    }

    function removeGalleryRole(address _address) public onlyAdminRole {
        require(
            hasGalleryRole(_address),
            "EphimeraAccessControls: Address must have gallery role"
        );
        _revokeRole(GALLERY_ROLE, _address);
        emit GalleryRemoved(_address);
    }

    function addCreatorRole(address _address) public onlyAdminRole {
        require(
            !hasGalleryRole(_address),
            "EphimeraAccessControls: Address already has gallery role and cannot have creator role at the same time"
        );

        require(
            !hasCreatorRole(_address),
            "EphimeraAccessControls: Address already has creator role"
        );

        _grantRole(CREATOR_ROLE, _address);
        emit NewArtistAdded(_address);
    }

    function removeCreatorRole(address _address) public onlyAdminRole {
        require(
            hasCreatorRole(_address),
            "EphimeraAccessControls: Address must have creator role"
        );
        _revokeRole(CREATOR_ROLE, _address);
        emit ArtistRemoved(_address);
    }

    /* Allows the DEFAULT_ADMIN_ROLE that controls all roles to be overridden thereby creating hierarchies */
    function setRoleAdmin(bytes32 _role, bytes32 _adminRole)
        external
        onlyAdminRole
    {
        _setRoleAdmin(_role, _adminRole);
    }

    function addArtistToGallery(address _gallery, address _artist)
        external
        onlyAdminRole
    {
        require(
            hasRole(GALLERY_ROLE, _gallery),
            "EphimeraAccessControls: Gallery address specified does not have the gallery role"
        );
        require(
            hasRole(CREATOR_ROLE, _artist),
            "EphimeraAccessControls: Artist address specified does not have the creator role"
        );
        require(
            !isArtistPartOfGallery(_gallery, _artist),
            "EphimeraAccessControls: Artist cannot be added twice to one gallery"
        );
        galleryToArtistMapping[_gallery][_artist] = true;
        artistToGalleriesMapping[_artist][_gallery] = true;

        emit ArtistAddedToGallery(_gallery, _artist, _msgSender());
    }

    function removeArtistFromGallery(address _gallery, address _artist)
        external
        onlyAdminRole
    {
        require(
            isArtistPartOfGallery(_gallery, _artist),
            "EphimeraAccessControls: Artist is not part of the gallery"
        );
        galleryToArtistMapping[_gallery][_artist] = false;
        artistToGalleriesMapping[_artist][_gallery] = false;

        emit ArtistRemovedFromGallery(_gallery, _artist, _msgSender());
    }
}