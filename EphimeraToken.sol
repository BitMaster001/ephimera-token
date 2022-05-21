// SPDX-License-Identifier: MIT

import '@openzeppelin/contracts/math/SafeMath.sol';
import '@openzeppelin/contracts/introspection/IERC165.sol';
import '@openzeppelin/contracts/introspection/ERC165.sol';
import '@openzeppelin/contracts/GSN/Context.sol';
import '@openzeppelin/contracts/utils/EnumerableSet.sol';
import '@openzeppelin/contracts/access/AccessControl.sol';
import './interfaces/IERC721Token.sol';
import './interfaces/IERC721Receiver.sol';
import './EphimeraAccessControls.sol';
import './EphimeraToken.sol';

pragma solidity 0.6.12;

/**
 * @title Ephimera Token contract (ephimera.com)
 * @author Ephimera 
 * @dev Ephimera's ERC-721 contract
 */
contract EphimeraToken is IERC721Token, ERC165, Context {
    using SafeMath for uint256;

    bytes4 private constant _INTERFACE_ID_ERC721 = 0x80ac58cd;
    bytes4 private constant _INTERFACE_ID_ERC721_METADATA = 0x5b5e139f;

    // Function selector for ERC721Receiver.onERC721Received 0x150b7a02
    bytes4 constant internal ERC721_RECEIVED = bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"));

    /// @dev the first token ID is 1
    uint256 public tokenPointer; 

    // Token name
    string public name = "Ephimera";

    // Token symbol
    string public symbol = "EPH";

    uint256 public totalSupply;

    // Mapping of tokenId => owner
    mapping(uint256 => address) internal owners;

    // Mapping of tokenId => approved address
    mapping(uint256 => address) internal approvals;

    // Mapping of owner => number of tokens owned
    mapping(address => uint256) internal balances;

    // Mapping of owner => operator => approved
    mapping(address => mapping(address => bool)) internal operatorApprovals;

    // Optional mapping for token URIs
    mapping(uint256 => string) internal tokenURIs;

    mapping(uint256 => uint256) public tokenTransferCount;

    EphimeraAccessControls public accessControls;

    constructor (EphimeraAccessControls _accessControls) public {
        accessControls = _accessControls;

        _registerInterface(_INTERFACE_ID_ERC721);
        _registerInterface(_INTERFACE_ID_ERC721_METADATA);
    }

    function isContract(address account) internal view returns (bool) {
        // According to EIP-1052, 0x0 is the value returned for not-yet created accounts
        // and 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 is returned
        // for accounts without code, i.e. `keccak256('')`
        bytes32 codehash;
        bytes32 accountHash = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;
        // solhint-disable-next-line no-inline-assembly
        assembly {codehash := extcodehash(account)}
        return (codehash != accountHash && codehash != 0x0);
    }

    function _checkOnERC721Received(address from, address to, uint256 tokenId, bytes memory _data)
    private returns (bool)
    {
        if (!isContract(to)) {
            return true;
        }
        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = to.call(abi.encodeWithSelector(
                IERC721Receiver(to).onERC721Received.selector,
                _msgSender(),
                from,
                tokenId,
                _data
            ));
        if (!success) {
            if (returndata.length > 0) {
                // solhint-disable-next-line no-inline-assembly
                assembly {
                    let returndata_size := mload(returndata)
                    revert(add(32, returndata), returndata_size)
                }
            } else {
                revert("ERC721: transfer to non ERC721Receiver implementer");
            }
        } else {
            bytes4 retval = abi.decode(returndata, (bytes4));
            return (retval == ERC721_RECEIVED);
        }
    }

    /// @notice sets URI of token metadata (e.g. IPFS hash of a token)
    /// @dev links an NFT to metadata URI
    /// @param _tokenId the identifier for an NFT 
    /// @param _uri data that the NFT is representing
    function setTokenURI(uint256 _tokenId, string calldata _uri) external {
        require(owners[_tokenId] != address(0), "EphimeraToken.setTokenURI: token does not exist.");
        require(accessControls.hasAdminRole(_msgSender()), "EphimeraToken.setTokenURI: caller is not a admin.");
        tokenURIs[_tokenId] = _uri;
    }

    /// @notice creates a new Ephimera art piece
    /// @dev mints a new NFT
    /// @param _to the address that the NFT is going to be issued to
    /// @param _uri data that the NFT is representing
    /// @return return an NFT id
    function mint(
        address _to,
        string calldata _uri
    ) external returns (uint256) {
        require(_to != address(0), "ERC721: mint to the zero address");
        require(accessControls.hasContractWhitelistRole(_msgSender()), "EphimeraToken.mint: caller is not whitelisted.");

        tokenPointer = tokenPointer.add(1);
        uint256 tokenId = tokenPointer;

        // Mint
        owners[tokenId] = _to;
        balances[_to] = balances[_to].add(1);

        // MetaData
        tokenURIs[tokenId] = _uri;
        totalSupply = totalSupply.add(1);

        tokenTransferCount[tokenId] = 1;

        // Single Transfer event for a single token
        emit Transfer(address(0), _to, tokenId);

        return tokenId;
    }

    /// @notice gets the data URI of a token
    /// @dev queries an NFT's URI
    /// @param _tokenId the identifier for an NFT
    /// @return return an NFT's tokenURI 
    function tokenURI(uint256 _tokenId) external view returns (string memory) {
        return tokenURIs[_tokenId];
    }

    /// @notice checks if an art exists
    /// @dev checks if an NFT exists
    /// @param _tokenId the identifier for an NFT 
    /// @return returns true if an NFT exists, else returns false
    function exists(uint256 _tokenId) external view returns (bool) {
        return owners[_tokenId] != address(0);
    }

    /// @notice allows owner and only owner of an art piece to delete it. 
    ///     This token will be gone forever; USE WITH CARE
    /// @dev owner can burn an NFT
    /// @param _tokenId the identifier for an NFT 
    function burn(uint256 _tokenId) external {
        require(_msgSender() == ownerOf(_tokenId), 
            "EphimeraToken.burn: Caller must be owner."
        );
        _burn(_tokenId);
    }

    function _burn(uint256 _tokenId)
    internal
    {
        address owner = owners[_tokenId];
        require(
            owner != address(0),
            "ERC721_ZERO_OWNER_ADDRESS"
        );

        owners[_tokenId] = address(0);
        balances[owner] = balances[owner].sub(1);
        totalSupply = totalSupply.sub(1);

        // clear metadata
        if (bytes(tokenURIs[_tokenId]).length != 0) {
            delete tokenURIs[_tokenId];
        }

        emit Transfer(
            owner,
            address(0),
            _tokenId
        );
    }

    /// @notice transfers the ownership of an NFT from one address to another address
    /// @dev wrapper function for the safeTransferFrom function below setting data to "".
    /// @param _from the current owner of the NFT
    /// @param _to the new owner
    /// @param _tokenId the identifier for the NFT to transfer
    function safeTransferFrom(address _from, address _to, uint256 _tokenId) override public {
        safeTransferFrom(_from, _to, _tokenId, "");
    }

    /// @notice transfers the ownership of an NFT from one address to another address
    /// @dev throws unless `msg.sender` is the current owner, an authorized
    ///      operator, or the approved address for this NFT. Throws if `_from` is
    ///      not the current owner. Throws if `_to` is the zero address. Throws if
    ///      `_tokenId` is not a valid NFT. When transfer is complete, this function
    ///      checks if `_to` is a smart contract (code size > 0). If so, it calls
    ///      `onERC721Received` on `_to` and throws if the return value is not
    ///      `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`.
    /// @param _from the current owner of the NFT
    /// @param _to the new owner
    /// @param _tokenId the identifier for the NFT to transfer
    /// @param _data additional data with no specified format; sent in call to `_to`
    function safeTransferFrom(
        address _from,
        address _to,
        uint256 _tokenId,
        bytes memory _data
    )
    override
    public
    {
        transferFrom(_from, _to, _tokenId);
        require(_checkOnERC721Received(_from, _to, _tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");
    }

    /// @notice change or reaffirm the approved address for an NFT
    /// @dev the zero address indicates there is no approved address.
    ///      Throws unless `msg.sender` is the current NFT owner, or an authorized
    ///      operator of the current owner.
    /// @param _approved the new approved NFT controller
    /// @param _tokenId the identifier of the NFT to approve
    function approve(address _approved, uint256 _tokenId)
    override
    external
    {
        address owner = ownerOf(_tokenId);
        require(_approved != owner, "ERC721: approval to current owner");
        
        require(
            _msgSender() == owner || isApprovedForAll(owner, _msgSender()),
            "ERC721: approve caller is not owner nor approved for all"
        );

        approvals[_tokenId] = _approved;
        emit Approval(
            owner,
            _approved,
            _tokenId
        );
    }

    /// @notice enable or disable approval for a third party ("operator") to manage
    ///         all of `msg.sender`'s assets
    /// @dev emits the ApprovalForAll event. The contract MUST allow
    ///      multiple operators per owner.
    /// @param _operator address to add to the set of authorized operators
    /// @param _approved true if the operator is approved, false to revoke approval
    function setApprovalForAll(address _operator, bool _approved)
    override
    external
    {
        require(_operator != _msgSender(), "ERC721: approve to caller");

        operatorApprovals[_msgSender()][_operator] = _approved;
        emit ApprovalForAll(
            _msgSender(),
            _operator,
            _approved
        );
    }

    /// @notice count all NFTs assigned to an owner
    /// @dev NFTs assigned to the zero address are considered invalid, and this
    ///      function throws for queries about the zero address.
    /// @param _owner an address to query
    /// @return the number of NFTs owned by `_owner`, possibly zero
    function balanceOf(address _owner)
    override
    external
    view
    returns (uint256)
    {
        require(
            _owner != address(0),
            "ERC721: owner query for nonexistent token"
        );
        return balances[_owner];
    }

    /// @notice transfer ownership of an NFT -- THE CALLER IS RESPONSIBLE
    ///         TO CONFIRM THAT `_to` IS CAPABLE OF RECEIVING NFTS OR ELSE
    ///         THEY MAY BE PERMANENTLY LOST
    /// @dev throws unless `msg.sender` is the current owner, an authorized
    ///      operator, or the approved address for this NFT. Throws if `_from` is
    ///      not the current owner. Throws if `_to` is the zero address. Throws if
    ///      `_tokenId` is not a valid NFT.
    /// @param _from the current owner of the NFT
    /// @param _to the new owner
    /// @param _tokenId the identifier of the NFT to transfer
    function transferFrom(
        address _from,
        address _to,
        uint256 _tokenId
    )
    override
    public
    {
        require(
            _to != address(0),
            "ERC721_ZERO_TO_ADDRESS"
        );

        address owner = ownerOf(_tokenId);
        require(
            _from == owner,
            "ERC721_OWNER_MISMATCH"
        );

        address spender = _msgSender();
        address approvedAddress = getApproved(_tokenId);
        require(
            spender == owner ||
            isApprovedForAll(owner, spender) ||
            approvedAddress == spender,
            "ERC721_INVALID_SPENDER"
        );

        if (approvedAddress != address(0)) {
            approvals[_tokenId] = address(0);
        }

        owners[_tokenId] = _to;
        balances[_from] = balances[_from].sub(1);
        balances[_to] = balances[_to].add(1);

        tokenTransferCount[_tokenId] = tokenTransferCount[_tokenId].add(1);

        emit Transfer(
            _from,
            _to,
            _tokenId
        );
    }

    /// @notice find the owner of an NFT
    /// @dev NFTs assigned to zero address are considered invalid, and queries
    ///      about them do throw.
    /// @param _tokenId the identifier for an NFT
    /// @return the address of the owner of the NFT
    function ownerOf(uint256 _tokenId)
    override
    public
    view
    returns (address)
    {
        address owner = owners[_tokenId];
        require(
            owner != address(0),
            "ERC721: owner query for nonexistent token"
        );
        return owner;
    }

    /// @notice get the approved address for a single NFT
    /// @dev throws if `_tokenId` is not a valid NFT.
    /// @param _tokenId the NFT to find the approved address for
    /// @return the approved address for this NFT, or the zero address if there is none
    function getApproved(uint256 _tokenId)
    override
    public
    view
    returns (address)
    {
        require(owners[_tokenId] != address(0), "ERC721: approved query for nonexistent token");
        return approvals[_tokenId];
    }

    /// @notice query if an address is an authorized operator for another address
    /// @param _owner the address that owns the NFTs
    /// @param _operator the address that acts on behalf of the owner
    /// @return true if `_operator` is an approved operator for `_owner`, false otherwise
    function isApprovedForAll(address _owner, address _operator)
    override
    public
    view
    returns (bool)
    {
        return operatorApprovals[_owner][_operator];
    }
}