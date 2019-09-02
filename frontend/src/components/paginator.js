import React, { Component, Fragment } from 'react';
import PropTypes from 'prop-types';
import { gettext } from '../utils/constants';


const propTypes = {
  gotoPreviousPage: PropTypes.func.isRequired,
  gotoNextPage: PropTypes.func.isRequired,
  currentPage: PropTypes.number.isRequired,
  hasNextPage: PropTypes.bool.isRequired,
  canResetPerPage: PropTypes.bool.isRequired,
  curPerPage: PropTypes.number,
  resetPerPage: PropTypes.func
};

class Paginator extends Component {

  resetPerPage = (perPage) => {
    this.props.resetPerPage(perPage);
  }

  goToPrevious = (e) => {
    e.preventDefault();
    this.props.gotoPreviousPage();
  } 

  goToNext = (e) => {
    e.preventDefault();
    this.props.gotoNextPage();
  } 

  render() {
    let { curPerPage } = this.props;
    return (
      <Fragment>
        <div className="my-6 text-center">
          {this.props.currentPage != 1 &&
            <a href="#" onClick={this.goToPrevious}>{gettext('Previous')}</a>
          }
          {this.props.hasNextPage &&
            <a href="#" onClick={this.goToNext} className="ml-4">{gettext('Next')}</a>
          }
          {this.props.canResetPerPage &&
            <Fragment>
              <span className="ml-2">{gettext('Per page:')}{' '}</span>
              {curPerPage == 25 ?
                <a>25</a>
                :
                <a href="#" onClick={(e) => {e.preventDefault(); return this.resetPerPage(25);}}>25</a>
              }
              {curPerPage == 50 ?
                <a className="ml-1">50</a>
                :
                <a href="#" className="ml-1" onClick={(e) => {e.preventDefault(); return this.resetPerPage(50);}}>50</a>
              }
              {curPerPage == 100 ?
                <a className="ml-1">100</a>
                :
                <a href="#" className="ml-1" onClick={(e) => {e.preventDefault(); return this.resetPerPage(100);}}>100</a>
              }
            </Fragment>
          }
        </div>
      </Fragment>
    );
  }
}

Paginator.propTypes = propTypes;

export default Paginator;
