import React from 'react';
import PropTypes from 'prop-types';
import TextTranslation from '../../utils/text-translation';
import TreeNodeView from './tree-node-view';
import ContextMenu from '../context-menu/context-menu';
import { hideMenu, showMenu } from '../context-menu/actions';
import { Utils } from '../../utils/utils';

const propTypes = {
  repoPermission: PropTypes.bool,
  isNodeMenuShow: PropTypes.bool.isRequired,
  treeData: PropTypes.object.isRequired,
  currentPath: PropTypes.string.isRequired,
  onMenuItemClick: PropTypes.func,
  onNodeClick: PropTypes.func.isRequired,
  onNodeExpanded: PropTypes.func.isRequired,
  onNodeCollapse: PropTypes.func.isRequired,
  onItemMove: PropTypes.func,
  currentRepoInfo: PropTypes.object,
  selectedDirentList: PropTypes.array,
  onItemsMove: PropTypes.func,
};

const PADDING_LEFT = 20;

class TreeView extends React.Component {

  constructor(props) {
    super(props);
    this.state = {
      isItemFreezed: false,
      isTreeViewDropTipShow: false,
    };
  }

  onItemMove = (repo, dirent, selectedPath, currentPath) => {
    this.props.onItemMove(repo, dirent, selectedPath, currentPath);
  }

  onNodeDragStart = (e, node) => {
    if (Utils.isIEBrower()) {
      return false;
    }
    let dragStartNodeData = {nodeDirent: node.object, nodeParentPath: node.parentNode.path, nodeRootPath: node.path};
    dragStartNodeData = JSON.stringify(dragStartNodeData);
    
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('applicaiton/drag-item-info', dragStartNodeData);
  }

  onNodeDragEnter = (e, node) => {
    if (Utils.isIEBrower()) {
      return false;
    }
    e.persist();
    if (e.target.className === 'tree-view tree ') {
      this.setState({
        isTreeViewDropTipShow: true,
      });
    }
  }

  onNodeDragMove = (e) => {
    if (Utils.isIEBrower()) {
      return false;
    }
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
  }

  onNodeDragLeave = (e, node) => {
    if (Utils.isIEBrower()) {
      return false;
    }
    if (e.target.className === 'tree-view tree tree-view-drop') {
      this.setState({
        isTreeViewDropTipShow: false,
      });
    }
  }

  onNodeDrop = (e, node) => {
    if (Utils.isIEBrower()) {
      return false;
    }
    if (e.dataTransfer.files.length) { // uploaded files
      return;
    }
    let dragStartNodeData = e.dataTransfer.getData('applicaiton/drag-item-info');
    dragStartNodeData = JSON.parse(dragStartNodeData);

    let {nodeDirent, nodeParentPath, nodeRootPath} = dragStartNodeData;
    let dropNodeData = node;

    if (Array.isArray(dragStartNodeData)) { //move items
      if (!dropNodeData) { //move items to root
        if (dragStartNodeData[0].nodeParentPath === '/') {
          this.setState({isTreeViewDropTipShow: false});
          return;
        }
        this.props.onItemsMove(this.props.currentRepoInfo, '/');
        this.setState({isTreeViewDropTipShow: false});
        return;
      }
      this.onMoveItems(dragStartNodeData, dropNodeData, this.props.currentRepoInfo, dropNodeData.path);
      return;
    }

    if (!dropNodeData) {
      if (nodeParentPath === '/') {
        this.setState({isTreeViewDropTipShow: false});
        return;
      }
      this.onItemMove(this.props.currentRepoInfo, nodeDirent, '/', nodeParentPath);
      this.setState({isTreeViewDropTipShow: false});
      return;
    }

    if (dropNodeData.object.type !== 'dir') {
      return;
    }

    if (nodeParentPath === dropNodeData.path) {
      return;
    }

    // copy the dirent to itself. eg: A/B -> A/B
    if (nodeParentPath === dropNodeData.parentNode.path) {
      if (dropNodeData.object.name === nodeDirent.name) {
        return;
      }
    }

    // copy the dirent to it's child. eg: A/B -> A/B/C
    if (dropNodeData.object.type === 'dir' && nodeDirent.type === 'dir') {
      if (dropNodeData.parentNode.path !== nodeParentPath) {
        let dropNodeDataArr = dropNodeData.path.split('/');
        let nodeRootPathArr = nodeRootPath.split('/');
        let flag = this.compareArray(nodeRootPathArr, dropNodeDataArr);
        if (flag) {
          return ;
        }
      }
    }

    this.onItemMove(this.props.currentRepoInfo, nodeDirent, dropNodeData.path, nodeParentPath);
  }

  onMoveItems = (dragStartNodeData, dropNodeData, destRepo, destDirentPath) => {
    let direntPaths = [];
    let destDirentPathDetail = destDirentPath.split('/');
    dragStartNodeData.forEach(dirent => {
      let path = dirent.nodeRootPath;
      direntPaths.push(path);
    });

    if (dropNodeData.object.type !== 'dir') {
      return;
    }

    // move dirents to one of them. eg: A/B, A/C -> A/B
    if (direntPaths.some(direntPath => { return direntPath === destDirentPath;})) {
      return;
    }

     // move dirents to current path
     if (dragStartNodeData[0].nodeParentPath && dragStartNodeData[0].nodeParentPath === dropNodeData.path ) {
      return;
    }


    // move dirents to one of their child. eg: A/B, A/D -> A/B/C
    let isChildPath = direntPaths.some(direntPath => {
      let direntPathdetail = direntPath.split('/');
      let flag = this.compareArray(direntPathdetail, destDirentPathDetail);
      return flag;
    });
    if (isChildPath) {
      return;
    }

    this.props.onItemsMove(destRepo, destDirentPath);
  }

  compareArray = (direntPathdetail, destDirentPathDetail) => {
    if (destDirentPathDetail.length < direntPathdetail.length) { 
      return false;
    } else {
      for (let i = 0; i < direntPathdetail.length; i++) { 
        if (direntPathdetail[i] !== destDirentPathDetail[i]) {
          return false;
        }
      }
    }
    return true;
  }

  freezeItem = () => {
    this.setState({isItemFreezed: true});
  }

  unfreezeItem = () => {
    this.setState({isItemFreezed: false});
  }

  onMenuItemClick = (operation, node) => {
    this.props.onMenuItemClick(operation, node);
    hideMenu();
  }

  onMouseDown = (event) => {
    event.stopPropagation();
    if (event.button === 2) {
      return;
    }
  }

  onContextMenu = (event) => {
    this.handleContextClick(event);
  }
  
  handleContextClick = (event, node) => {
    event.preventDefault();
    event.stopPropagation();
    
    if (!this.props.isNodeMenuShow) {
      return;
    }

    let currentRepoInfo = this.props.currentRepoInfo;

    if (currentRepoInfo.permission === 'cloud-edit' || currentRepoInfo.permission === 'preview') {
      return '';
    }
    
    let x = event.clientX || (event.touches && event.touches[0].pageX);
    let y = event.clientY || (event.touches && event.touches[0].pageY);

    if (this.props.posX) {
      x -= this.props.posX;
    }
    if (this.props.posY) {
      y -= this.props.posY;
    }

    hideMenu();

    let menuList = this.getMenuList(node);
    
    let showMenuConfig = {
      id: 'tree-node-contextmenu',
      position: { x, y },
      target: event.target,
      currentObject: node,
      menuList: menuList,
    };
    
    showMenu(showMenuConfig);
  }

  getMenuList = (node) => {
    let menuList = [];

    let { NEW_FOLDER, NEW_FILE, COPY, MOVE, RENAME, DELETE, OPEN_VIA_CLIENT } = TextTranslation;

    if (!node) {
      return [NEW_FOLDER, NEW_FILE];
    }

    if (node.object.type === 'dir') {
      menuList = [NEW_FOLDER, NEW_FILE, COPY, MOVE, RENAME, DELETE];
    } else {
      menuList = [RENAME, DELETE, COPY, MOVE, OPEN_VIA_CLIENT];
    } 

    return menuList;
  }

  onShowMenu = () => {
    this.freezeItem();
  }

  onHideMenu = () => {
    this.unfreezeItem();
  }

  render() {
    return (
      <div 
        className={`tree-view tree ${this.state.isTreeViewDropTipShow ? 'tree-view-drop' : ''}`} 
        onDrop={this.onNodeDrop} 
        onDragEnter={this.onNodeDragEnter} 
        onDragLeave={this.onNodeDragLeave}
        onMouseDown={this.onMouseDown}
        onContextMenu={this.onContextMenu}
      >
        <TreeNodeView 
          repoPermission={this.props.repoPermission}
          node={this.props.treeData.root}
          currentPath={this.props.currentPath}
          paddingLeft={PADDING_LEFT}
          isNodeMenuShow={this.props.isNodeMenuShow}
          isItemFreezed={this.state.isItemFreezed}
          onNodeClick={this.props.onNodeClick}
          onMenuItemClick={this.props.onMenuItemClick}
          onNodeExpanded={this.props.onNodeExpanded}
          onNodeCollapse={this.props.onNodeCollapse}
          onNodeDragStart={this.onNodeDragStart}
          freezeItem={this.freezeItem}
          unfreezeItem={this.unfreezeItem}
          onNodeDragMove={this.onNodeDragMove}
          onNodeDrop={this.onNodeDrop}
          onNodeDragEnter={this.onNodeDragEnter}
          onNodeDragLeave={this.onNodeDragLeave}
          handleContextClick={this.handleContextClick}
        />
        <ContextMenu 
          id={'tree-node-contextmenu'}
          onMenuItemClick={this.onMenuItemClick}
          onHideMenu={this.onHideMenu}
          onShowMenu={this.onShowMenu}
        />
      </div>
    );
  }
}

TreeView.propTypes = propTypes;

export default TreeView;
